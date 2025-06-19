package androidx.glance.appwidget.action;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class c extends r implements Function1 {
    public static final c b = new c(1, 0);
    public static final c c = new c(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
        }
        return (androidx.glance.action.f) obj;
    }
}
