package androidx.compose.ui.text.font;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.data.repository.school.exceptions.CreateNewSchoolException;
import kotlin.coroutines.CoroutineContext;

/* loaded from: classes.dex */
public final class o extends kotlin.coroutines.a implements kotlinx.coroutines.A {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ o(kotlin.coroutines.l lVar, int i) {
        super(lVar);
        this.a = i;
    }

    private final void B(CoroutineContext coroutineContext, Throwable th) {
    }

    private final void a0(CoroutineContext coroutineContext, Throwable th) {
    }

    private final void c0(CoroutineContext coroutineContext, Throwable th) {
    }

    private final void r(CoroutineContext coroutineContext, Throwable th) {
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) {
        switch (this.a) {
            case 2:
                boolean z = th instanceof CreateNewSchoolException;
                break;
            case 3:
                timber.log.c.a.p(th);
                break;
            case 4:
                timber.log.c.a.p(th);
                break;
            case 5:
                timber.log.c.a.p(th);
                break;
            case 7:
                timber.log.c.a.h(th);
                break;
            case 8:
                timber.log.c.a.a("In-App Review Prompt failed: %s", th.getMessage());
                break;
            case 9:
                timber.log.c.a.p(th);
                break;
            case 10:
                timber.log.c.a.h(th);
                break;
            case 11:
                timber.log.c.a.o("Coroutine exception caught: " + th, new Object[0]);
                break;
            case 12:
                timber.log.c.a.o(AbstractC0147y.d("Could not enable Snowplow. ", th.getMessage()), new Object[0]);
                break;
        }
    }
}
