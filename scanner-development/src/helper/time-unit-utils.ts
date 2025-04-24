export const millis = {
  // milis to specified time unit
  to: {
    seconds: (n: number): number => n / 1000,
    minutes: (n: number): number => millis.to.seconds(n) / 60,
  },

  // specified time unit to milis
  from: {
    seconds: (n: number): number => n * 1000,
    minutes: (n: number): number => millis.from.seconds(n) * 60,
  },
};
