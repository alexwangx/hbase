/*
 * Copyright The Apache Software Foundation
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.apache.hadoop.hbase.thrift;

import com.google.common.base.Joiner;
import com.google.protobuf.BlockingService;
import com.google.protobuf.RpcController;
import com.google.protobuf.ServiceException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.*;
import org.apache.hadoop.hbase.client.ClusterConnection;
import org.apache.hadoop.hbase.client.HTableInterface;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessorEnvironment;
import org.apache.hadoop.hbase.ipc.*;
import org.apache.hadoop.hbase.protobuf.generated.AuthenticationProtos;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.RegionServerServices;
import org.apache.hadoop.hbase.security.SecurityInfo;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.token.AuthenticationTokenSecretManager;
import org.apache.hadoop.hbase.security.token.TestTokenAuthentication;
import org.apache.hadoop.hbase.security.token.TokenProvider;
import org.apache.hadoop.hbase.testclassification.LargeTests;
import org.apache.hadoop.hbase.thrift.ThriftServerRunner.ImplType;
import org.apache.hadoop.hbase.thrift.generated.Hbase;
import org.apache.hadoop.hbase.util.*;
import org.apache.hadoop.hbase.zookeeper.MetaTableLocator;
import org.apache.hadoop.hbase.zookeeper.ZKClusterId;
import org.apache.hadoop.hbase.zookeeper.ZooKeeperWatcher;
import org.apache.hadoop.net.DNS;
import org.apache.hadoop.security.authorize.PolicyProvider;
import org.apache.hadoop.security.authorize.Service;
import org.apache.hadoop.security.token.SecretManager;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TCompactProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.server.TServer;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION;
import static org.apache.hadoop.hbase.thrift.ThriftServerRunner.ImplType.THREAD_POOL;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Start the HBase Thrift server on a random port through the command-line
 * interface and talk to it from client side.
 */
@Category(LargeTests.class)
@RunWith(Parameterized.class)
public class TestThriftServerCmdLineKrb {

  private static final Log LOG =
      LogFactory.getLog(TestThriftServerCmdLineKrb.class);

  private ImplType implType;
  private boolean specifyFramed;
  private boolean specifyBindIP;
  private boolean specifyCompact;

  private static final HBaseTestingUtility TEST_UTIL =
      new HBaseTestingUtility();

  private Thread cmdLineThread;
  private volatile Exception cmdLineException;

  private Exception clientSideException;

  private ThriftServer thriftServer;
  private int port;

  @Parameters
  public static Collection<Object[]> getParameters() {
    Collection<Object[]> parameters = new ArrayList<Object[]>();
    for (ImplType implType : ImplType.values()) {
      for (boolean specifyFramed : new boolean[] {false, true}) {
        for (boolean specifyBindIP : new boolean[] {false, true}) {
          if (specifyBindIP && !implType.canSpecifyBindIP) {
            continue;
          }
          for (boolean specifyCompact : new boolean[] {false, true}) {
//            LOG.info("ALEX_DEBUG: " + implType.toString()
//                    +", "+  specifyFramed +", "+ specifyBindIP  +", "+  specifyCompact);
            parameters.add(new Object[]{implType, specifyFramed,
                specifyBindIP, specifyCompact});
          }
        }
      }
    }
//    LOG.info("ALEX_DEBUG parameters: " + parameters.toString());
    return parameters;
  }

  public TestThriftServerCmdLineKrb(ImplType implType, boolean specifyFramed,
                                    boolean specifyBindIP, boolean specifyCompact) {
    this.implType = implType;
    this.specifyFramed = specifyFramed;
    this.specifyBindIP = specifyBindIP;
    this.specifyCompact = specifyCompact;
    LOG.debug(getParametersString());
  }

  private String getParametersString() {
    return "implType=" + implType + ", " +
        "specifyFramed=" + specifyFramed + ", " +
        "specifyBindIP=" + specifyBindIP + ", " +
        "specifyCompact=" + specifyCompact;
  }

//  @BeforeClass
//  public static void setUpBeforeClass() throws Exception {
//    TEST_UTIL.getConfiguration().setBoolean("hbase.table.sanity.checks", false);
//    TEST_UTIL.startMiniCluster();
//    //ensure that server time increments every time we do an operation, otherwise
//    //successive puts having the same timestamp will override each other
//    EnvironmentEdgeManagerTestHelper.injectEdge(new IncrementingEnvironmentEdge());
//  }


    static {
        // Setting whatever system properties after recommendation from
        // http://docs.oracle.com/javase/6/docs/technotes/guides/security/jgss/tutorials/KerberosReq.html
        System.setProperty("java.security.krb5.realm", "hbase");
        System.setProperty("java.security.krb5.kdc", "blah");
    }
    public interface AuthenticationServiceSecurityInfo {}

    /**
     * Basic server process for RPC authentication testing
     */
    private static class TokenServer extends TokenProvider
            implements AuthenticationProtos.AuthenticationService.BlockingInterface, Runnable, Server {
        private static final Log LOG = LogFactory.getLog(TokenServer.class);
        private Configuration conf;
        private RpcServerInterface rpcServer;
        private InetSocketAddress isa;
        private ZooKeeperWatcher zookeeper;
        private Sleeper sleeper;
        private boolean started = false;
        private boolean aborted = false;
        private boolean stopped = false;
        private long startcode;

        public TokenServer(Configuration conf) throws IOException {
            this.conf = conf;
            this.startcode = EnvironmentEdgeManager.currentTime();
            // Server to handle client requests.
            String hostname =
                    Strings.domainNamePointerToHostName(DNS.getDefaultHost("default", "default"));
            int port = 0;
            // Creation of an ISA will force a resolve.
            InetSocketAddress initialIsa = new InetSocketAddress(hostname, port);
            if (initialIsa.getAddress() == null) {
                throw new IllegalArgumentException("Failed resolve of " + initialIsa);
            }
            final List<RpcServer.BlockingServiceAndInterface> sai =
                    new ArrayList<RpcServer.BlockingServiceAndInterface>(1);
            BlockingService service =
                    AuthenticationProtos.AuthenticationService.newReflectiveBlockingService(this);
            sai.add(new RpcServer.BlockingServiceAndInterface(service,
                    AuthenticationProtos.AuthenticationService.BlockingInterface.class));
            this.rpcServer =
                    new RpcServer(this, "tokenServer", sai, initialIsa, conf, new FifoRpcScheduler(conf, 1));
            InetSocketAddress address = rpcServer.getListenerAddress();
            if (address == null) {
                throw new IOException("Listener channel is closed");
            }
            this.isa = address;
            this.sleeper = new Sleeper(1000, this);
        }

        @Override
        public Configuration getConfiguration() {
            return conf;
        }

        @Override
        public ClusterConnection getConnection() {
            return null;
        }

        @Override
        public MetaTableLocator getMetaTableLocator() {
            return null;
        }

        @Override
        public ZooKeeperWatcher getZooKeeper() {
            return zookeeper;
        }

        @Override
        public CoordinatedStateManager getCoordinatedStateManager() {
            return null;
        }

        @Override
        public boolean isAborted() {
            return aborted;
        }

        @Override
        public ServerName getServerName() {
            return ServerName.valueOf(isa.getHostName(), isa.getPort(), startcode);
        }

        @Override
        public void abort(String reason, Throwable error) {
            LOG.fatal("Aborting on: "+reason, error);
            this.aborted = true;
            this.stopped = true;
            sleeper.skipSleepCycle();
        }

        private void initialize() throws IOException {
            // ZK configuration must _not_ have hbase.security.authentication or it will require SASL auth
            Configuration zkConf = new Configuration(conf);
            zkConf.set(User.HBASE_SECURITY_CONF_KEY, "simple");
            this.zookeeper = new ZooKeeperWatcher(zkConf, TokenServer.class.getSimpleName(),
                    this, true);
            this.rpcServer.start();

            // mock RegionServerServices to provide to coprocessor environment
            final RegionServerServices mockServices = TEST_UTIL.createMockRegionServerService(rpcServer);

            // mock up coprocessor environment
            super.start(new RegionCoprocessorEnvironment() {
                @Override
                public HRegion getRegion() { return null; }

                @Override
                public RegionServerServices getRegionServerServices() {
                    return mockServices;
                }

                @Override
                public ConcurrentMap<String, Object> getSharedData() { return null; }

                @Override
                public int getVersion() { return 0; }

                @Override
                public String getHBaseVersion() { return null; }

                @Override
                public Coprocessor getInstance() { return null; }

                @Override
                public int getPriority() { return 0; }

                @Override
                public int getLoadSequence() { return 0; }

                @Override
                public Configuration getConfiguration() { return conf; }

                @Override
                public HTableInterface getTable(TableName tableName) throws IOException
                { return null; }

                @Override
                public HTableInterface getTable(TableName tableName, ExecutorService service)
                        throws IOException {
                    return null;
                }

                @Override
                public ClassLoader getClassLoader() {
                    return Thread.currentThread().getContextClassLoader();
                }

                @Override
                public HRegionInfo getRegionInfo() {
                    return null;
                }
            });

            started = true;
        }

        public void run() {
            try {
                initialize();
                while (!stopped) {
                    this.sleeper.sleep();
                }
            } catch (Exception e) {
                abort(e.getMessage(), e);
            }
            this.rpcServer.stop();
        }

        public boolean isStarted() {
            return started;
        }

        @Override
        public void stop(String reason) {
            LOG.info("Stopping due to: "+reason);
            this.stopped = true;
            sleeper.skipSleepCycle();
        }

        @Override
        public boolean isStopped() {
            return stopped;
        }

        public InetSocketAddress getAddress() {
            return isa;
        }

        public SecretManager<? extends TokenIdentifier> getSecretManager() {
            return ((RpcServer)rpcServer).getSecretManager();
        }

        @Override
        public AuthenticationProtos.GetAuthenticationTokenResponse getAuthenticationToken(
                RpcController controller, AuthenticationProtos.GetAuthenticationTokenRequest request)
                throws ServiceException {
            LOG.debug("Authentication token request from " + RpcServer.getRequestUserName());
            // ignore passed in controller -- it's always null
            ServerRpcController serverController = new ServerRpcController();
            BlockingRpcCallback<AuthenticationProtos.GetAuthenticationTokenResponse> callback =
                    new BlockingRpcCallback<AuthenticationProtos.GetAuthenticationTokenResponse>();
            getAuthenticationToken(serverController, request, callback);
            try {
                serverController.checkFailed();
                return callback.get();
            } catch (IOException ioe) {
                throw new ServiceException(ioe);
            }
        }

        @Override
        public AuthenticationProtos.WhoAmIResponse whoAmI(
                RpcController controller, AuthenticationProtos.WhoAmIRequest request)
                throws ServiceException {
            LOG.debug("whoAmI() request from " + RpcServer.getRequestUserName());
            // ignore passed in controller -- it's always null
            ServerRpcController serverController = new ServerRpcController();
            BlockingRpcCallback<AuthenticationProtos.WhoAmIResponse> callback =
                    new BlockingRpcCallback<AuthenticationProtos.WhoAmIResponse>();
            whoAmI(serverController, request, callback);
            try {
                serverController.checkFailed();
                return callback.get();
            } catch (IOException ioe) {
                throw new ServiceException(ioe);
            }
        }

        @Override
        public ChoreService getChoreService() {
            return null;
        }
    }


//    private static HBaseTestingUtility TEST_UTIL;
    private static TokenServer server;
    private static Thread serverThread;
    private static AuthenticationTokenSecretManager secretManager;
    private static ClusterId clusterId = new ClusterId();

    @BeforeClass
    public static void setupBeforeClass() throws Exception {
//        TEST_UTIL = new HBaseTestingUtility();
        TEST_UTIL.startMiniZKCluster();
        // register token type for protocol
        SecurityInfo.addInfo(AuthenticationProtos.AuthenticationService.getDescriptor().getName(),
                new SecurityInfo("hbase.test.kerberos.principal",
                        AuthenticationProtos.TokenIdentifier.Kind.HBASE_AUTH_TOKEN));
        // security settings only added after startup so that ZK does not require SASL
        Configuration conf = TEST_UTIL.getConfiguration();
        conf.set("hadoop.security.authentication", "kerberos");
        conf.set("hbase.security.authentication", "kerberos");
        conf.setBoolean(HADOOP_SECURITY_AUTHORIZATION, true);
        server = new TokenServer(conf);
        serverThread = new Thread(server);
        Threads.setDaemonThreadRunning(serverThread, "TokenServer:"+server.getServerName().toString());
        // wait for startup
        while (!server.isStarted() && !server.isStopped()) {
            Thread.sleep(10);
        }
        server.rpcServer.refreshAuthManager(new PolicyProvider() {
            @Override
            public Service[] getServices() {
                return new Service [] {
                        new Service("security.client.protocol.acl",
                                AuthenticationProtos.AuthenticationService.BlockingInterface.class)};
            }
        });
        ZKClusterId.setClusterId(server.getZooKeeper(), clusterId);
        secretManager = (AuthenticationTokenSecretManager)server.getSecretManager();
        while(secretManager.getCurrentKey() == null) {
            Thread.sleep(1);
        }
    }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    TEST_UTIL.shutdownMiniCluster();
    EnvironmentEdgeManager.reset();
  }

  private void startCmdLineThread(final String[] args) {
    LOG.info("Starting HBase Thrift server with command line: " + Joiner.on(" ").join(args));

    cmdLineException = null;
    cmdLineThread = new Thread(new Runnable() {
      @Override
      public void run() {
        try {
          thriftServer.doMain(args);
        } catch (Exception e) {
          cmdLineException = e;
        }
      }
    });
    cmdLineThread.setName(ThriftServer.class.getSimpleName() +
        "-cmdline");
    cmdLineThread.start();
  }

  @Test(timeout=600000)
  public void testRunThriftServer() throws Exception {
    List<String> args = new ArrayList<String>();
        implType = THREAD_POOL;
    if (implType != null) {
      String serverTypeOption = implType.toString();
      LOG.info("ALEX_DEBUG server type option :" + serverTypeOption);
      assertTrue(serverTypeOption.startsWith("-"));
      args.add(serverTypeOption);
    }
    port = HBaseTestingUtility.randomFreePort();
    args.add("-" + ThriftServer.PORT_OPTION);
    args.add(String.valueOf(port));
    args.add("-infoport");
    int infoPort = HBaseTestingUtility.randomFreePort();
    args.add(String.valueOf(infoPort));

    if (specifyFramed) {
      args.add("-" + ThriftServer.FRAMED_OPTION);
    }
    if (specifyBindIP) {
      args.add("-" + ThriftServer.BIND_OPTION);
      args.add(InetAddress.getLocalHost().getHostName());
    }
    if (specifyCompact) {
      args.add("-" + ThriftServer.COMPACT_OPTION);
    }
    args.add("start");


    LOG.info("ALEX_DEBUG hbase.security.authorization : " + TEST_UTIL.getConfiguration().get("hbase.security.authorization"));
    LOG.info("ALEX_DEBUG hbase.security.authentication : " + TEST_UTIL.getConfiguration().get("hbase.security.authentication"));

    thriftServer = new ThriftServer(TEST_UTIL.getConfiguration());
    startCmdLineThread(args.toArray(new String[args.size()]));

    // wait up to 10s for the server to start
    for (int i = 0; i < 100
        && (thriftServer.serverRunner == null || thriftServer.serverRunner.tserver == null); i++) {
      Thread.sleep(100);
    }

    Class<? extends TServer> expectedClass = implType != null ?
        implType.serverClass : TBoundedThreadPoolServer.class;
    assertEquals(expectedClass,
                 thriftServer.serverRunner.tserver.getClass());

    try {
      talkToThriftServer();
    } catch (Exception ex) {
      clientSideException = ex;
    } finally {
      stopCmdLineThread();
    }

    if (clientSideException != null) {
      LOG.error("Thrift client threw an exception. Parameters:" +
          getParametersString(), clientSideException);
      throw new Exception(clientSideException);
    }
  }

  private static volatile boolean tableCreated = false;

  private void talkToThriftServer() throws Exception {
    TSocket sock = new TSocket(InetAddress.getLocalHost().getHostName(),
        port);
    TTransport transport = sock;
    if (specifyFramed || implType.isAlwaysFramed) {
      transport = new TFramedTransport(transport);
    }

    sock.open();
    try {
      TProtocol prot;
      if (specifyCompact) {
        prot = new TCompactProtocol(transport);
      } else {
        prot = new TBinaryProtocol(transport);
      }
      Hbase.Client client = new Hbase.Client(prot);
      if (!tableCreated){
        TestThriftServer.createTestTables(client);
        tableCreated = true;
      }
      TestThriftServer.checkTableList(client);

    } finally {
      sock.close();
    }
  }

  private void stopCmdLineThread() throws Exception {
    LOG.debug("Stopping " + implType.simpleClassName() + " Thrift server");
    thriftServer.stop();
    cmdLineThread.join();
    if (cmdLineException != null) {
      LOG.error("Command-line invocation of HBase Thrift server threw an " +
          "exception", cmdLineException);
      throw new Exception(cmdLineException);
    }
  }
}

