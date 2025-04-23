export class DynamicCodeExecution {
    methodA() {}
    methodB() {}
    methodC() {}  // New line here

    async addItemDCE(resource) {
        const data = await this[resource.name]();
        return data;
    }
}

export class IncompleteSanitizationOfString {
    sanitize(input) {
        return input.replace('{', '').replace('}', '');
    }
}

export class UnsafeDeserialization {
    parseUserData(jsonString) {
        return JSON.parse(jsonString);
    }
}

// Moved this
export class DenialOfServiceVulnerability {
    replaceWithRegex(str, find, replace) {
        return str.replace(new RegExp(find, 'g'), replace);
    }
}
