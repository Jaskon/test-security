const stats = {
  totalRequests: 0,
  totalEtagRequests: 0,
  noCachedEtagRequests: 0,
  successfulEtagRequest: 0,
  expiredEtagsRequests: 0,
  noCachedRequests: 0,
};

const requestStats = () => {
  return {
    stats,
    addTotalRequest: () => (stats.totalRequests += 1),
    addTotalEtagRequest: () => (stats.totalEtagRequests += 1),
    addSuccessfulEtagRequest: () => (stats.successfulEtagRequest += 1),
    addExpiredEtagRequest: () => (stats.expiredEtagsRequests += 1),
    addNoCachedEtagRequest: () => (stats.noCachedEtagRequests += 1),
    addNoCachedRequests: () => (stats.noCachedRequests += 1),
  };
};

export default requestStats;
