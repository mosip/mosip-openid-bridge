package io.mosip.kernel.auth.defaultadapter.config;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.hc.client5.http.HttpRoute;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.pool.PoolStats;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import jakarta.annotation.PostConstruct;

public class ConnectionPoolStatsLogger {

	private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionPoolStatsLogger.class);

	@Value("${mosip.kernel.http.connection-pool.log-frequency-seconds:60}")
	private int logFrequencySeconds;

	@Value("${mosip.kernel.http.connection-pool.log-enabled:true}")
	private boolean logEnabled;

	private final PoolingHttpClientConnectionManager selfTokenRestTemplateConnManager;

	public ConnectionPoolStatsLogger(PoolingHttpClientConnectionManager selfTokenRestTemplateConnManager) {
		this.selfTokenRestTemplateConnManager = selfTokenRestTemplateConnManager;
	}

	@PostConstruct
	private void init() {
		if (logEnabled) {
			ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
			taskScheduler.setPoolSize(1);
			taskScheduler.setThreadNamePrefix("conn-pool-stats-");
			taskScheduler.initialize();
			taskScheduler.scheduleAtFixedRate(new ConnectionPoolStatsTask(), 
					TimeUnit.SECONDS.toMillis(logFrequencySeconds));
			LOGGER.info("selfTokenRestTemplate connection pool stats logging enabled with frequency: {} seconds", 
					logFrequencySeconds);
		}
	}

	private class ConnectionPoolStatsTask implements Runnable {
		@Override
		public void run() {
			try {
				if (selfTokenRestTemplateConnManager == null) {
					return;
				}
				
				PoolStats totalStats = selfTokenRestTemplateConnManager.getTotalStats();
				LOGGER.info("selfTokenRestTemplate ConnectionPool Total - Leased: {}, Pending: {}, Available: {}, Max: {}",
						totalStats.getLeased(),
						totalStats.getPending(),
						totalStats.getAvailable(),
						totalStats.getMax());
				
				logPerHostStats();
			} catch (Exception e) {
				LOGGER.warn("Error logging connection pool stats: {}", e.getMessage());
			}
		}

		private void logPerHostStats() {
			Set<HttpRoute> routes = selfTokenRestTemplateConnManager.getRoutes();
			if (routes == null || routes.isEmpty()) {
				LOGGER.debug("selfTokenRestTemplate ConnectionPool - No active routes");
				return;
			}
			
			int maxPerRoute = selfTokenRestTemplateConnManager.getDefaultMaxPerRoute();
			
			for (HttpRoute route : routes) {
				PoolStats routeStats = selfTokenRestTemplateConnManager.getStats(route);
				String host = route.getTargetHost().toHostString();
				
				LOGGER.info("selfTokenRestTemplate ConnectionPool Host [{}] - Leased: {}, Pending: {}, Available: {}, MaxPerRoute: {}",
						host,
						routeStats.getLeased(),
						routeStats.getPending(),
						routeStats.getAvailable(),
						maxPerRoute);
			}
		}
	}
}
