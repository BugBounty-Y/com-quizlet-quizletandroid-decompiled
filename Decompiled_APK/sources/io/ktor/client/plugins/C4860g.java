package io.ktor.client.plugins;

/* renamed from: io.ktor.client.plugins.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4860g extends io.ktor.http.content.b {
    public final io.ktor.http.d a;
    public final long b;
    public final /* synthetic */ Object c;

    public C4860g(io.ktor.http.d dVar, Object obj) {
        this.c = obj;
        if (dVar == null) {
            io.ktor.http.d dVar2 = io.ktor.http.b.a;
            dVar = io.ktor.http.b.a;
        }
        this.a = dVar;
        this.b = ((byte[]) obj).length;
    }

    @Override // io.ktor.http.content.c
    public final Long a() {
        return Long.valueOf(this.b);
    }

    @Override // io.ktor.http.content.c
    public final io.ktor.http.d b() {
        return this.a;
    }

    @Override // io.ktor.http.content.b
    public final byte[] d() {
        return (byte[]) this.c;
    }
}
