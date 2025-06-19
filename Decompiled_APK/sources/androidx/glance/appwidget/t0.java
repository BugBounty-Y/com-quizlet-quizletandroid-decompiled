package androidx.glance.appwidget;

import android.content.Context;
import androidx.datastore.core.C1072d;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t0 implements androidx.glance.state.g {
    public static final t0 a = new t0();

    @Override // androidx.glance.state.g
    public final File a(Context context, String str) {
        return K6.a(context, str);
    }

    @Override // androidx.glance.state.g
    public final Object b(Context context, String str) {
        androidx.glance.appwidget.proto.l serializer = androidx.glance.appwidget.proto.l.a;
        s0 produceFile = new s0(context, str, 0);
        kotlin.collections.K migrations = kotlin.collections.K.a;
        kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
        kotlinx.coroutines.internal.d scope = kotlinx.coroutines.E.c(kotlinx.coroutines.scheduling.d.b.plus(kotlinx.coroutines.E.e()));
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(migrations, "migrations");
        Intrinsics.checkNotNullParameter(scope, "scope");
        Intrinsics.checkNotNullParameter(produceFile, "produceFile");
        androidx.datastore.core.U storage = new androidx.datastore.core.U(serializer, produceFile);
        Intrinsics.checkNotNullParameter(storage, "storage");
        Intrinsics.checkNotNullParameter(migrations, "migrations");
        Intrinsics.checkNotNullParameter(scope, "scope");
        com.quizlet.shared.usecase.folderstudymaterials.a aVar = new com.quizlet.shared.usecase.folderstudymaterials.a(3);
        Intrinsics.checkNotNullParameter(migrations, "migrations");
        return new androidx.datastore.core.P(storage, kotlin.collections.A.b(new C1072d(migrations, null)), aVar, scope);
    }
}
