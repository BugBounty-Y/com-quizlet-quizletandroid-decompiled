package androidx.compose.ui.platform.actionmodecallback;

import android.graphics.Rect;
import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import androidx.camera.camera2.internal.c0;
import androidx.compose.foundation.text.I;
import androidx.compose.ui.geometry.c;
import androidx.compose.ui.input.nestedscroll.b;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a extends ActionMode.Callback2 {
    public final c0 a;

    public a(c0 c0Var) {
        this.a = c0Var;
    }

    /* JADX WARN: Type inference failed for: r5v2, types: [java.lang.Object, kotlin.jvm.functions.Function0] */
    /* JADX WARN: Type inference failed for: r5v7, types: [java.lang.Object, kotlin.jvm.functions.Function0] */
    @Override // android.view.ActionMode.Callback
    public final boolean onActionItemClicked(ActionMode actionMode, MenuItem menuItem) {
        c0 c0Var = this.a;
        c0Var.getClass();
        Intrinsics.d(menuItem);
        int itemId = menuItem.getItemId();
        if (itemId == 0) {
            ?? r5 = c0Var.d;
            if (r5 != 0) {
                r5.invoke();
            }
        } else if (itemId == 1) {
            I i = (I) c0Var.e;
            if (i != null) {
                i.invoke();
            }
        } else if (itemId == 2) {
            I i2 = (I) c0Var.f;
            if (i2 != null) {
                i2.invoke();
            }
        } else {
            if (itemId != 3) {
                return false;
            }
            ?? r52 = c0Var.g;
            if (r52 != 0) {
                r52.invoke();
            }
        }
        if (actionMode != null) {
            actionMode.finish();
        }
        return true;
    }

    @Override // android.view.ActionMode.Callback
    public final boolean onCreateActionMode(ActionMode actionMode, Menu menu) {
        c0 c0Var = this.a;
        c0Var.getClass();
        if (menu == null) {
            throw new IllegalArgumentException("onCreateActionMode requires a non-null menu");
        }
        if (actionMode == null) {
            throw new IllegalArgumentException("onCreateActionMode requires a non-null mode");
        }
        if (c0Var.d != null) {
            c0.h(1, menu);
        }
        if (((I) c0Var.e) != null) {
            c0.h(2, menu);
        }
        if (((I) c0Var.f) != null) {
            c0.h(3, menu);
        }
        if (c0Var.g != null) {
            c0.h(4, menu);
        }
        return true;
    }

    @Override // android.view.ActionMode.Callback
    public final void onDestroyActionMode(ActionMode actionMode) {
        ((b) this.a.b).invoke();
    }

    @Override // android.view.ActionMode.Callback2
    public final void onGetContentRect(ActionMode actionMode, View view, Rect rect) {
        c cVar = (c) this.a.c;
        if (rect != null) {
            rect.set((int) cVar.a, (int) cVar.b, (int) cVar.c, (int) cVar.d);
        }
    }

    /* JADX WARN: Type inference failed for: r4v3, types: [java.lang.Object, kotlin.jvm.functions.Function0] */
    /* JADX WARN: Type inference failed for: r4v6, types: [java.lang.Object, kotlin.jvm.functions.Function0] */
    @Override // android.view.ActionMode.Callback
    public final boolean onPrepareActionMode(ActionMode actionMode, Menu menu) {
        c0 c0Var = this.a;
        c0Var.getClass();
        if (actionMode == null || menu == null) {
            return false;
        }
        c0.i(menu, 1, c0Var.d);
        c0.i(menu, 2, (I) c0Var.e);
        c0.i(menu, 3, (I) c0Var.f);
        c0.i(menu, 4, c0Var.g);
        return true;
    }
}
