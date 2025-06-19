package androidx.emoji2.text;

import android.os.Build;
import com.google.android.gms.internal.mlkit_vision_barcode.X6;
import com.google.android.gms.internal.mlkit_vision_barcode.Y6;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class e extends X6 {
    public final /* synthetic */ f a;

    public e(f fVar) {
        this.a = fVar;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X6
    public final void c(Throwable th) {
        ((j) this.a.b).e(th);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X6
    public final void d(com.quizlet.data.repository.explanations.textbook.a aVar) {
        f fVar = this.a;
        fVar.c = aVar;
        com.quizlet.data.repository.explanations.textbook.a aVar2 = (com.quizlet.data.repository.explanations.textbook.a) fVar.c;
        j jVar = (j) fVar.b;
        fVar.a = new com.quizlet.data.repository.folderwithcreator.e(aVar2, jVar.g, jVar.i, Build.VERSION.SDK_INT >= 34 ? o.a() : Y6.b());
        j jVar2 = (j) fVar.b;
        jVar2.getClass();
        ArrayList arrayList = new ArrayList();
        jVar2.a.writeLock().lock();
        try {
            jVar2.c = 1;
            arrayList.addAll(jVar2.b);
            jVar2.b.clear();
            jVar2.a.writeLock().unlock();
            jVar2.d.post(new androidx.core.provider.a(arrayList, jVar2.c, (Throwable) null));
        } catch (Throwable th) {
            jVar2.a.writeLock().unlock();
            throw th;
        }
    }
}
