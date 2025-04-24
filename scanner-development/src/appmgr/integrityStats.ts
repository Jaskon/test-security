const stats = {
  totalImages: 0,
  skippedImages: 0,
  verified: 0,
  notVerified: 0,
};

const integrityStats = () => {
  return {
    stats,
    addTotalImage: () => (stats.totalImages += 1),
    addSkippedImage: () => (stats.skippedImages += 1),
    addVerifiedImage: () => (stats.verified += 1),
    addNotVerifiedImage: () => (stats.notVerified += 1),
  };
};

export default integrityStats;
