package com.iabtcf.utils;

import java.util.function.Function;

/* loaded from: classes2.dex */
public final class i implements g, j, Function {
    public volatile boolean b = false;
    public volatile boolean c = false;
    public volatile Integer d;
    public final /* synthetic */ int e;
    public final /* synthetic */ l f;

    public i(l lVar, int i) {
        this.e = i;
        this.f = lVar;
    }

    @Override // com.iabtcf.utils.g
    public final boolean a() {
        switch (this.e) {
            case 0:
                return this.f.c();
            default:
                return l.values()[this.f.ordinal() - 1].c();
        }
    }

    @Override // java.util.function.Function
    public final Object apply(Object obj) {
        a aVar = (a) obj;
        if (!this.b) {
            this.c = a();
            this.b = true;
        }
        if (this.c) {
            return b(aVar);
        }
        if (this.d == null) {
            this.d = b(aVar);
        }
        return this.d;
    }

    public final Integer b(a aVar) {
        switch (this.e) {
            case 0:
                l lVar = this.f;
                return Integer.valueOf(lVar.b(aVar) + lVar.a(aVar));
            default:
                l lVar2 = l.values()[this.f.ordinal() - 1];
                return Integer.valueOf(lVar2.b(aVar) + lVar2.a(aVar));
        }
    }
}
