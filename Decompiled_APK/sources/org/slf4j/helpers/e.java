package org.slf4j.helpers;

import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes3.dex */
public final class e implements org.slf4j.spi.a {
    public final /* synthetic */ int a;
    public final org.slf4j.a b;

    public e(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new i();
                new ConcurrentHashMap();
                new ThreadLocal();
                new b();
                break;
            default:
                this.b = new d();
                new ConcurrentHashMap();
                break;
        }
    }

    @Override // org.slf4j.spi.a
    public final org.slf4j.a a() {
        switch (this.a) {
            case 0:
                return (d) this.b;
            default:
                return (i) this.b;
        }
    }

    @Override // org.slf4j.spi.a
    public final String b() {
        switch (this.a) {
            case 0:
                return "2.0.99";
            default:
                throw new UnsupportedOperationException();
        }
    }
}
