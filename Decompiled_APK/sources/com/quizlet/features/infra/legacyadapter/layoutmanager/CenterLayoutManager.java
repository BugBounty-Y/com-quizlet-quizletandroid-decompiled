package com.quizlet.features.infra.legacyadapter.layoutmanager;

import android.content.Context;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.S;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class CenterLayoutManager extends LinearLayoutManager {
    public final a E;

    public static final class a extends S {
        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(@NotNull Context context) {
            super(context);
            Intrinsics.checkNotNullParameter(context, "context");
        }

        @Override // androidx.recyclerview.widget.S
        public final int a(int i, int i2, int i3, int i4, int i5) {
            return (((i4 - i3) / 2) + i3) - (((i2 - i) / 2) + i);
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public CenterLayoutManager(@NotNull Context context) {
        this(context, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void F0(RecyclerView recyclerView, B0 state, int i) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        Intrinsics.checkNotNullParameter(state, "state");
        a aVar = this.E;
        aVar.a = i;
        G0(aVar);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CenterLayoutManager(Context context, int i) {
        super(1);
        Intrinsics.checkNotNullParameter(context, "context");
        this.E = new a(context);
    }
}
