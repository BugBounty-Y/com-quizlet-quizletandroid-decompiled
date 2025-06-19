package androidx.emoji2.text;

import com.google.android.gms.internal.mlkit_vision_barcode.X6;
import java.util.concurrent.ThreadPoolExecutor;

/* loaded from: classes.dex */
public final class l extends X6 {
    public final /* synthetic */ X6 a;
    public final /* synthetic */ ThreadPoolExecutor b;

    public l(X6 x6, ThreadPoolExecutor threadPoolExecutor) {
        this.a = x6;
        this.b = threadPoolExecutor;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X6
    public final void c(Throwable th) {
        ThreadPoolExecutor threadPoolExecutor = this.b;
        try {
            this.a.c(th);
        } finally {
            threadPoolExecutor.shutdown();
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X6
    public final void d(com.quizlet.data.repository.explanations.textbook.a aVar) {
        ThreadPoolExecutor threadPoolExecutor = this.b;
        try {
            this.a.d(aVar);
        } finally {
            threadPoolExecutor.shutdown();
        }
    }
}
