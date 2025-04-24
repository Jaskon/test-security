class JsonHelper {
  uuid: string;

  constructor(uuid: string) {
    this.uuid = uuid;
  }

  updateObjects(obj, key, newVal) {
    var newValue = newVal;
    var objects = [];
    for (var i in obj) {
      if (!obj.hasOwnProperty(i)) continue;
      if (typeof obj[i] == "object") {
        objects = objects.concat(this.updateObjects(obj[i], key, newValue));
      }
      if (i == key) {
        obj[key] = newVal;
      }
    }
    return obj;
  }

  lookupArrayVal(obj, k, defaultArray = true) {
    if (obj == null) {
      return defaultArray ? [] : null;
    }

    const res = obj[k];
    if (res == undefined) {
      return defaultArray ? [] : null;
    }

    return res;
  }
}

export default JsonHelper;
