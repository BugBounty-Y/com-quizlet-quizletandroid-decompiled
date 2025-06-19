package com.quizlet.ads.ui.activity;

import androidx.lifecycle.Z;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.InterfaceC4953l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Z, InterfaceC4953l {
    public final /* synthetic */ int a;
    public final /* synthetic */ C4956o b;

    /* JADX WARN: Multi-variable type inference failed */
    public a(int i, Function1 function) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(function, "function");
                this.b = (C4956o) function;
                break;
            case 2:
                Intrinsics.checkNotNullParameter(function, "function");
                this.b = (C4956o) function;
                break;
            case 3:
                Intrinsics.checkNotNullParameter(function, "function");
                this.b = (C4956o) function;
                break;
            default:
                Intrinsics.checkNotNullParameter(function, "function");
                this.b = (C4956o) function;
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.o] */
    /* JADX WARN: Type inference failed for: r0v2, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.o] */
    /* JADX WARN: Type inference failed for: r0v3, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.o] */
    /* JADX WARN: Type inference failed for: r0v4, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.o] */
    @Override // androidx.lifecycle.Z
    public final /* synthetic */ void a(Object obj) {
        switch (this.a) {
            case 0:
                this.b.invoke(obj);
                break;
            case 1:
                this.b.invoke(obj);
                break;
            case 2:
                this.b.invoke(obj);
                break;
            default:
                this.b.invoke(obj);
                break;
        }
    }

    public final boolean equals(Object obj) {
        switch (this.a) {
            case 0:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 1:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 2:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            default:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
        }
        return Intrinsics.b(getFunctionDelegate(), ((InterfaceC4953l) obj).getFunctionDelegate());
    }

    @Override // kotlin.jvm.internal.InterfaceC4953l
    public final InterfaceC4938g getFunctionDelegate() {
        switch (this.a) {
        }
        return this.b;
    }

    public final int hashCode() {
        switch (this.a) {
        }
        return getFunctionDelegate().hashCode();
    }
}
