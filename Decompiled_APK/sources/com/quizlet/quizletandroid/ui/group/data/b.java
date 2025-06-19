package com.quizlet.quizletandroid.ui.group.data;

import com.quizlet.infra.legacysyncengine.net.c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final c a;
    public final long b;

    public b(long j, c loader) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.b = j;
        this.a = loader;
    }

    public b(c loader, long j, int i) {
        switch (i) {
            case 2:
                Intrinsics.checkNotNullParameter(loader, "loader");
                this.a = loader;
                this.b = j;
                break;
            default:
                Intrinsics.checkNotNullParameter(loader, "loader");
                this.a = loader;
                this.b = j;
                break;
        }
    }
}
