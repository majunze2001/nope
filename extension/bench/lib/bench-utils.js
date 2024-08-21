const DOMAIN = 'nope-tools.org';
const N = 1000;

class Timer {
  constructor(name) {
    this.name = name;
    this.cur = 0;
    this.arr = [];
  }

  get() {
    return this.arr;
  }
  set(start) {
    if (start) {
      if (this.cur) {
        console.log('Overwriting, logic err');
        process.exit(1);
      }
      this.cur = performance.now();
    } else {
      this.arr.push(performance.now() - this.cur);
      this.cur = 0;
      return this.arr;
    }
  }
  display() {
    if (!this.arr.length) return;

    // Sort the array
    const sortedArr = this.arr.slice().sort((a, b) => a - b);

    // Calculate the number of elements to remove from each end
    const numElementsToRemove = Math.floor(sortedArr.length * 0.01);

    // Create a new array without the top and bottom 1% elements
    const trimmedArr = sortedArr.slice(
      numElementsToRemove,
      sortedArr.length - numElementsToRemove,
    );

    // Ensure there is still data to display after trimming
    if (!trimmedArr.length) {
      console.log(this.name, 'No data to display after removing outliers.');
      return;
    }

    // Calculate the average, range, and standard deviation on the trimmed array
    console.log(
      this.name,
      `Average=${trimmedArr.reduce((s, t) => s + t, 0) /
        trimmedArr.length} ms,`,
      `range ${Math.min(...trimmedArr)}-${Math.max(...trimmedArr)} ms`,
      `std: ${getStandardDeviation(trimmedArr)} ms`,
    );
  }
}

function getStandardDeviation(array) {
  const n = array.length;
  const mean = array.reduce((a, b) => a + b) / n;
  return Math.sqrt(
    array.map(x => Math.pow(x - mean, 2)).reduce((a, b) => a + b) / n,
  );
}

module.exports = {
  Timer,
  N,
  DOMAIN,
};
