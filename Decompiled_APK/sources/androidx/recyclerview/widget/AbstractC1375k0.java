package androidx.recyclerview.widget;

import android.graphics.Canvas;
import android.graphics.Rect;
import android.view.View;
import androidx.annotation.NonNull;

/* renamed from: androidx.recyclerview.widget.k0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1375k0 {
    @Deprecated
    public void getItemOffsets(@NonNull Rect rect, int i, @NonNull RecyclerView recyclerView) {
        rect.set(0, 0, 0, 0);
    }

    @Deprecated
    public void onDraw(@NonNull Canvas canvas, @NonNull RecyclerView recyclerView) {
    }

    @Deprecated
    public void onDrawOver(@NonNull Canvas canvas, @NonNull RecyclerView recyclerView) {
    }

    public void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, B0 b0) {
        getItemOffsets(rect, ((C1383o0) view.getLayoutParams()).a.getLayoutPosition(), recyclerView);
    }

    public void onDraw(@NonNull Canvas canvas, @NonNull RecyclerView recyclerView, @NonNull B0 b0) {
        onDraw(canvas, recyclerView);
    }

    public void onDrawOver(@NonNull Canvas canvas, @NonNull RecyclerView recyclerView, @NonNull B0 b0) {
        onDrawOver(canvas, recyclerView);
    }
}
