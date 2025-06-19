package androidx.compose.ui.semantics;

import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class m {
    public static final AtomicInteger a = new AtomicInteger(0);

    public static final androidx.compose.ui.q a(androidx.compose.ui.q qVar, boolean z, Function1 function1) {
        return qVar.g(new AppendedSemanticsElement(function1, z));
    }
}
