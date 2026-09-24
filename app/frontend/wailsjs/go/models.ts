export namespace certview {
	
	export class BasicConstraints {
	    ca: boolean;
	    pathLen?: number;
	
	    static createFrom(source: any = {}) {
	        return new BasicConstraints(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ca = source["ca"];
	        this.pathLen = source["pathLen"];
	    }
	}
	export class Fingerprints {
	    sha1: string;
	    sha256: string;
	
	    static createFrom(source: any = {}) {
	        return new Fingerprints(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sha1 = source["sha1"];
	        this.sha256 = source["sha256"];
	    }
	}
	export class GenericExtension {
	    oid: string;
	    critical: boolean;
	    hex: string;
	
	    static createFrom(source: any = {}) {
	        return new GenericExtension(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.oid = source["oid"];
	        this.critical = source["critical"];
	        this.hex = source["hex"];
	    }
	}
	export class NameAttribute {
	    oid: string;
	    name: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new NameAttribute(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.oid = source["oid"];
	        this.name = source["name"];
	        this.value = source["value"];
	    }
	}
	export class Cert {
	    version: number;
	    serialHex: string;
	    serialDec: string;
	    signatureAlgorithm: string;
	    signatureAlgorithmOid: string;
	    signatureAlgorithmParams: string;
	    issuer: string;
	    issuerAttributes: NameAttribute[];
	    subject: string;
	    subjectAttributes: NameAttribute[];
	    notBefore: string;
	    notAfter: string;
	    publicKeyAlgorithm: string;
	    publicKeyAlgorithmOid: string;
	    publicKeyHex: string;
	    subjectAlternativeNames: string[];
	    keyUsage: string[];
	    extendedKeyUsage: string[];
	    basicConstraints?: BasicConstraints;
	    subjectKeyId: string;
	    authorityKeyId: string;
	    extensions: GenericExtension[];
	    fingerprints: Fingerprints;
	
	    static createFrom(source: any = {}) {
	        return new Cert(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.serialHex = source["serialHex"];
	        this.serialDec = source["serialDec"];
	        this.signatureAlgorithm = source["signatureAlgorithm"];
	        this.signatureAlgorithmOid = source["signatureAlgorithmOid"];
	        this.signatureAlgorithmParams = source["signatureAlgorithmParams"];
	        this.issuer = source["issuer"];
	        this.issuerAttributes = this.convertValues(source["issuerAttributes"], NameAttribute);
	        this.subject = source["subject"];
	        this.subjectAttributes = this.convertValues(source["subjectAttributes"], NameAttribute);
	        this.notBefore = source["notBefore"];
	        this.notAfter = source["notAfter"];
	        this.publicKeyAlgorithm = source["publicKeyAlgorithm"];
	        this.publicKeyAlgorithmOid = source["publicKeyAlgorithmOid"];
	        this.publicKeyHex = source["publicKeyHex"];
	        this.subjectAlternativeNames = source["subjectAlternativeNames"];
	        this.keyUsage = source["keyUsage"];
	        this.extendedKeyUsage = source["extendedKeyUsage"];
	        this.basicConstraints = this.convertValues(source["basicConstraints"], BasicConstraints);
	        this.subjectKeyId = source["subjectKeyId"];
	        this.authorityKeyId = source["authorityKeyId"];
	        this.extensions = this.convertValues(source["extensions"], GenericExtension);
	        this.fingerprints = this.convertValues(source["fingerprints"], Fingerprints);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	

}

export namespace main {
	
	export class NodeDTO {
	    offset: number;
	    headerLen: number;
	    length: number;
	    depth: number;
	    tag: string;
	    tagName: string;
	    oidName: string;
	    value: string;
	    hasChildren: boolean;
	    children: NodeDTO[];
	
	    static createFrom(source: any = {}) {
	        return new NodeDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.offset = source["offset"];
	        this.headerLen = source["headerLen"];
	        this.length = source["length"];
	        this.depth = source["depth"];
	        this.tag = source["tag"];
	        this.tagName = source["tagName"];
	        this.oidName = source["oidName"];
	        this.value = source["value"];
	        this.hasChildren = source["hasChildren"];
	        this.children = this.convertValues(source["children"], NodeDTO);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FileView {
	    path: string;
	    encoding: string;
	    label: string;
	    typeHint: string;
	    root: NodeDTO;
	    hexPreview: string;
	
	    static createFrom(source: any = {}) {
	        return new FileView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.encoding = source["encoding"];
	        this.label = source["label"];
	        this.typeHint = source["typeHint"];
	        this.root = this.convertValues(source["root"], NodeDTO);
	        this.hexPreview = source["hexPreview"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

