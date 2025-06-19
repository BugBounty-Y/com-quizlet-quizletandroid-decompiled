package com.google.android.gms.internal.mlkit_common;

import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final /* synthetic */ class p implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.google.mlkit.common.sdkinternal.i b;

    public /* synthetic */ p(com.google.mlkit.common.sdkinternal.i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        switch (this.a) {
        }
        return this.b.a();
    }
}
