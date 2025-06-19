package io.ktor.util.pipeline;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.q;
import kotlin.r;

/* loaded from: classes3.dex */
public final class k implements kotlin.coroutines.h, kotlin.coroutines.jvm.internal.d {
    public int a = Integer.MIN_VALUE;
    public final /* synthetic */ l b;

    public k(l lVar) {
        this.b = lVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v1, types: [kotlin.coroutines.h[]] */
    /* JADX WARN: Type inference failed for: r2v2 */
    @Override // kotlin.coroutines.jvm.internal.d
    public final kotlin.coroutines.jvm.internal.d getCallerFrame() {
        j jVar = j.a;
        int i = this.a;
        l lVar = this.b;
        if (i == Integer.MIN_VALUE) {
            this.a = lVar.f;
        }
        int i2 = this.a;
        if (i2 < 0) {
            this.a = Integer.MIN_VALUE;
            jVar = null;
        } else {
            try {
                ?? r2 = lVar.e[i2];
                if (r2 != 0) {
                    this.a = i2 - 1;
                    jVar = r2;
                }
            } catch (Throwable unused) {
            }
        }
        if (jVar instanceof kotlin.coroutines.jvm.internal.d) {
            return jVar;
        }
        return null;
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        l lVar = this.b;
        kotlin.coroutines.h[] hVarArr = lVar.e;
        int i = lVar.f;
        kotlin.coroutines.h hVar = hVarArr[i];
        if (hVar != this && hVar != null) {
            return hVar.getContext();
        }
        int i2 = i - 1;
        while (i2 >= 0) {
            int i3 = i2 - 1;
            kotlin.coroutines.h hVar2 = lVar.e[i2];
            if (hVar2 != this && hVar2 != null) {
                return hVar2.getContext();
            }
            i2 = i3;
        }
        throw new IllegalStateException("Not started");
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        p pVar = r.b;
        boolean z = obj instanceof q;
        l lVar = this.b;
        if (!z) {
            lVar.e(false);
            return;
        }
        Throwable thA = r.a(obj);
        Intrinsics.d(thA);
        lVar.g(Z.b(thA));
    }
}
