package androidx.datastore.core.okio;

import androidx.datastore.core.m0;
import androidx.datastore.core.n0;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;
import okio.t;
import okio.x;

/* loaded from: classes.dex */
public final class e implements m0 {
    public static final LinkedHashSet e = new LinkedHashSet();
    public static final com.quizlet.shared.usecase.folderstudymaterials.b f = new com.quizlet.shared.usecase.folderstudymaterials.b(3);
    public final t a;
    public final com.quizlet.data.repository.school.membership.a b;
    public final androidx.credentials.playservices.controllers.BeginSignIn.d c;
    public final u d;

    public e(t fileSystem, com.quizlet.data.repository.school.membership.a serializer, androidx.credentials.playservices.controllers.BeginSignIn.d producePath) {
        c coordinatorProducer = c.a;
        Intrinsics.checkNotNullParameter(fileSystem, "fileSystem");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(coordinatorProducer, "coordinatorProducer");
        Intrinsics.checkNotNullParameter(producePath, "producePath");
        this.a = fileSystem;
        this.b = serializer;
        this.c = producePath;
        this.d = l.b(new d(this, 0));
    }

    @Override // androidx.datastore.core.m0
    public final n0 a() {
        String strS = ((x) this.d.getValue()).a.s();
        synchronized (f) {
            LinkedHashSet linkedHashSet = e;
            if (linkedHashSet.contains(strS)) {
                throw new IllegalStateException(("There are multiple DataStores active for the same file: " + strS + ". You should either maintain your DataStore as a singleton or confirm that there is no two DataStore's active on the same file (by confirming that the scope is cancelled).").toString());
            }
            linkedHashSet.add(strS);
        }
        t tVar = this.a;
        x xVar = (x) this.d.getValue();
        com.quizlet.data.repository.school.membership.a aVar = this.b;
        x path = (x) this.d.getValue();
        t tVar2 = this.a;
        Intrinsics.checkNotNullParameter(path, "path");
        Intrinsics.checkNotNullParameter(tVar2, "<anonymous parameter 1>");
        Intrinsics.checkNotNullParameter(path, "path");
        return new h(tVar, xVar, aVar, N6.a(com.quizlet.quizletandroid.ui.folder.logging.a.f(path.a.s(), true).a.s()), new d(this, 1));
    }
}
