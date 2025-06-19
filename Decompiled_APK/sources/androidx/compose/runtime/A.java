package androidx.compose.runtime;

import kotlin.KotlinNothingValueException;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class A extends kotlin.jvm.internal.r implements Function0 {
    public static final A a = new A(0);

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        r.d("Unexpected call to default provider");
        throw new KotlinNothingValueException();
    }
}
