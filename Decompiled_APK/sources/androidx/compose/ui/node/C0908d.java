package androidx.compose.ui.node;

/* renamed from: androidx.compose.ui.node.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0908d implements androidx.compose.ui.modifier.g {
    public final /* synthetic */ int a;

    public /* synthetic */ C0908d(int i) {
        this.a = i;
    }

    public int a() {
        switch (this.a) {
            case 1:
                return 16;
            default:
                return 8;
        }
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // androidx.compose.ui.modifier.g
    public Object d(androidx.compose.ui.modifier.h hVar) {
        return hVar.a.invoke();
    }
}
