package androidx.core.view;

import android.view.ViewParent;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;

/* renamed from: androidx.core.view.a0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1037a0 extends C4956o implements Function1 {
    public static final C1037a0 a = new C1037a0();

    public C1037a0() {
        super(1, ViewParent.class, "getParent", "getParent()Landroid/view/ViewParent;", 0);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((ViewParent) obj).getParent();
    }
}
