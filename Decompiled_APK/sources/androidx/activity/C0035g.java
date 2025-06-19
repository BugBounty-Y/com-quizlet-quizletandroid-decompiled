package androidx.activity;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.activity.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0035g implements androidx.activity.contextaware.b {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;

    public /* synthetic */ C0035g(s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    @Override // androidx.activity.contextaware.b
    public final void a(s it2) {
        switch (this.a) {
            case 0:
                s.l(this.b, it2);
                return;
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                androidx.core.content.g gVar = (com.quizlet.baseui.base.b) this.b;
                boolean z = gVar instanceof dagger.hilt.android.internal.migration.a;
                if (z) {
                    Class<?> cls = gVar.getClass();
                    if (z) {
                        return;
                    }
                    throw new IllegalArgumentException("'" + cls + "' is not an optionally injected android entry point. Check that you have annotated the class with both @AndroidEntryPoint and @OptionalInject.");
                }
                return;
        }
    }
}
