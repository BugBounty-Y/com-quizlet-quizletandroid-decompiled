package io.ktor.http;

import kotlin.collections.K;

/* loaded from: classes3.dex */
public abstract class b {
    public static final d a;

    static {
        K k = K.a;
        new d("application", "*", k);
        new d("application", "atom+xml", k);
        new d("application", "cbor", k);
        new d("application", "json", k);
        new d("application", "hal+json", k);
        new d("application", "javascript", k);
        a = new d("application", "octet-stream", k);
        new d("application", "rss+xml", k);
        new d("application", "soap+xml", k);
        new d("application", "xml", k);
        new d("application", "xml-dtd", k);
        new d("application", "zip", k);
        new d("application", "gzip", k);
        new d("application", "x-www-form-urlencoded", k);
        new d("application", "pdf", k);
        new d("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet", k);
        new d("application", "vnd.openxmlformats-officedocument.wordprocessingml.document", k);
        new d("application", "vnd.openxmlformats-officedocument.presentationml.presentation", k);
        new d("application", "protobuf", k);
        new d("application", "wasm", k);
        new d("application", "problem+json", k);
        new d("application", "problem+xml", k);
    }
}
