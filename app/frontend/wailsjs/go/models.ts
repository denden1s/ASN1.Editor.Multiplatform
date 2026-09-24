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

