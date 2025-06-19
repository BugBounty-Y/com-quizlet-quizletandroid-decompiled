package com.quizlet.diagrams.layoutmanager;

import android.content.Context;
import androidx.navigation.compose.w;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DiagramCardLayoutManager extends FlashCardsLayoutManager {
    public static final /* synthetic */ int I = 0;
    public final u H;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public DiagramCardLayoutManager(@NotNull Context context) {
        this(context, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int H() {
        return ((Number) this.H.getValue()).intValue();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int I() {
        return ((Number) this.H.getValue()).intValue();
    }

    @Override // com.quizlet.diagrams.layoutmanager.FlashCardsLayoutManager
    public final int p1(int i, int i2, int i3, int i4) {
        boolean z = i < 0;
        if (z) {
            return i4;
        }
        if (z) {
            throw new NoWhenBranchMatchedException();
        }
        return i4 + 1;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DiagramCardLayoutManager(Context context, int i) {
        super(0);
        Intrinsics.checkNotNullParameter(context, "context");
        this.E = context.getResources().getDisplayMetrics().density * 386.0885886511961d * 160.0d * FlashCardsLayoutManager.G;
        this.H = l.b(new w(context, 2));
    }
}
