package androidx.glance.appwidget;

import android.os.Bundle;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.glance.appwidget.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1217u extends kotlin.jvm.internal.r implements Function0 {
    public static final C1217u b = new C1217u(0, 0);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C1217u(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return new Bundle();
            case 1:
                int i = C1177j0.a;
                return new C();
            default:
                int i2 = v0.a;
                return new D();
        }
    }
}
