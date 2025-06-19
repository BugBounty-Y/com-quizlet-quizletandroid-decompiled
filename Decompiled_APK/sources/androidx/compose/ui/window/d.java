package androidx.compose.ui.window;

import java.util.UUID;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class d extends kotlin.jvm.internal.r implements Function0 {
    public static final d b = new d(0, 0);
    public static final d c = new d(0, 1);
    public static final d d = new d(0, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
        }
        return UUID.randomUUID();
    }
}
