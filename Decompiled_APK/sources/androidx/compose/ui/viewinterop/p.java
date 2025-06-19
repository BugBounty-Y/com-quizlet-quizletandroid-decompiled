package androidx.compose.ui.viewinterop;

import android.content.Context;
import android.os.Parcelable;
import android.util.SparseArray;
import android.view.View;
import androidx.compose.runtime.C0810n;
import androidx.compose.ui.node.g0;
import androidx.compose.ui.platform.AbstractC0930a;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class p extends i {
    public Function1 A;
    public Function1 B;
    public final View w;
    public final androidx.compose.ui.input.nestedscroll.e x;
    public androidx.compose.runtime.saveable.h y;
    public Function1 z;

    public p(Context context, Function1 function1, C0810n c0810n, androidx.compose.runtime.saveable.i iVar, int i, g0 g0Var) {
        View view = (View) function1.invoke(context);
        androidx.compose.ui.input.nestedscroll.e eVar = new androidx.compose.ui.input.nestedscroll.e();
        super(context, c0810n, i, eVar, view, g0Var);
        this.w = view;
        this.x = eVar;
        setClipChildren(false);
        String strValueOf = String.valueOf(i);
        Object objC = iVar != null ? iVar.c(strValueOf) : null;
        SparseArray<Parcelable> sparseArray = objC instanceof SparseArray ? (SparseArray) objC : null;
        if (sparseArray != null) {
            view.restoreHierarchyState(sparseArray);
        }
        if (iVar != null) {
            setSavableRegistryEntry(iVar.d(strValueOf, new h(this, 2)));
        }
        a aVar = a.f;
        this.z = aVar;
        this.A = aVar;
        this.B = aVar;
    }

    public static final void l(p pVar) {
        pVar.setSavableRegistryEntry(null);
    }

    private final void setSavableRegistryEntry(androidx.compose.runtime.saveable.h hVar) {
        androidx.compose.runtime.saveable.h hVar2 = this.y;
        if (hVar2 != null) {
            ((com.quizlet.data.repository.course.membership.c) hVar2).q();
        }
        this.y = hVar;
    }

    @NotNull
    public final androidx.compose.ui.input.nestedscroll.e getDispatcher() {
        return this.x;
    }

    @NotNull
    public final Function1<View, Unit> getReleaseBlock() {
        return this.B;
    }

    @NotNull
    public final Function1<View, Unit> getResetBlock() {
        return this.A;
    }

    public /* bridge */ /* synthetic */ AbstractC0930a getSubCompositionView() {
        return null;
    }

    @NotNull
    public final Function1<View, Unit> getUpdateBlock() {
        return this.z;
    }

    @NotNull
    public View getViewRoot() {
        return this;
    }

    public final void setReleaseBlock(@NotNull Function1<View, Unit> function1) {
        this.B = function1;
        setRelease(new h(this, 3));
    }

    public final void setResetBlock(@NotNull Function1<View, Unit> function1) {
        this.A = function1;
        setReset(new h(this, 4));
    }

    public final void setUpdateBlock(@NotNull Function1<View, Unit> function1) {
        this.z = function1;
        setUpdate(new h(this, 5));
    }
}
