package androidx.core.os;

import android.os.OutcomeReceiver;
import androidx.glance.appwidget.protobuf.Z;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C5028l;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class c extends AtomicBoolean implements OutcomeReceiver {

    @NotNull
    private final kotlin.coroutines.h<Object> a;

    public c(C5028l c5028l) {
        super(false);
        this.a = c5028l;
    }

    public final void onError(Throwable th) {
        if (compareAndSet(false, true)) {
            kotlin.coroutines.h<Object> hVar = this.a;
            p pVar = r.b;
            hVar.resumeWith(Z.b(th));
        }
    }

    public final void onResult(Object obj) {
        if (compareAndSet(false, true)) {
            kotlin.coroutines.h<Object> hVar = this.a;
            p pVar = r.b;
            hVar.resumeWith(obj);
        }
    }

    @Override // java.util.concurrent.atomic.AtomicBoolean
    public final String toString() {
        return "ContinuationOutcomeReceiver(outcomeReceived = " + get() + ')';
    }
}
