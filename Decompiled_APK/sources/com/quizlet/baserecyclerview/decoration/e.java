package com.quizlet.baserecyclerview.decoration;

import android.content.Context;
import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.AbstractC1375k0;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends AbstractC1375k0 {
    public final /* synthetic */ int a = 1;
    public final int b;

    public e(int i) {
        this.b = i;
    }

    @Override // androidx.recyclerview.widget.AbstractC1375k0
    public final void getItemOffsets(Rect outRect, View view, RecyclerView parent, B0 state) {
        int i = this.b;
        int i2 = this.a;
        Intrinsics.checkNotNullParameter(outRect, "outRect");
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(state, "state");
        switch (i2) {
            case 0:
                d dVar = d.a;
                outRect.set(0, 0, 0, i);
                break;
            default:
                super.getItemOffsets(outRect, view, parent, state);
                Object tag = view.getTag(R.id.unifiedRecyclerView);
                if (tag == null) {
                    tag = Boolean.FALSE;
                }
                if (tag.equals(Boolean.TRUE)) {
                    outRect.set(0, 0, 0, i);
                    break;
                }
                break;
        }
    }

    public e(Context context, int i) {
        d orientation = d.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(orientation, "orientation");
        this.b = context.getResources().getDimensionPixelSize(i);
    }
}
