package com.quizlet.shared.persistence.di;

import android.content.Context;
import androidx.compose.ui.node.B;
import app.cash.sqldelight.driver.android.d;
import app.cash.sqldelight.driver.android.i;
import assistantMode.enums.s;
import assistantMode.refactored.types.f;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import com.quizlet.shared.persistence.studiableMetadata.e;
import java.util.Arrays;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import org.koin.core.error.InstanceCreationException;

/* loaded from: classes3.dex */
public final class c extends r implements Function2 {
    public static final c b = new c(2, 0);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Exception {
        switch (this.a) {
            case 0:
                org.koin.core.scope.a single = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single, "$this$single");
                Intrinsics.checkNotNullParameter(it2, "it");
                Object objB = null;
                try {
                    objB = single.b(null, K.a(e.class), null);
                } catch (Exception e) {
                    if (!(e instanceof InstanceCreationException ? true : e instanceof IllegalStateException)) {
                        throw e;
                    }
                    ((j) single.b.c).d("|- Encountered " + K.a(e.getClass()).f() + ": Falling back to null!");
                }
                e eVar = (e) objB;
                return eVar == null ? com.quizlet.shared.persistence.studiableMetadata.a.a : eVar;
            case 1:
                org.koin.core.scope.a aVar = (org.koin.core.scope.a) obj;
                com.quizlet.local.sqldelight.a databaseDriverFactory = (com.quizlet.local.sqldelight.a) aVar.a(null, B.q(aVar, "$this$single", (org.koin.core.parameter.a) obj2, "it", com.quizlet.local.sqldelight.a.class), null);
                Intrinsics.checkNotNullParameter(databaseDriverFactory, "databaseDriverFactory");
                Intrinsics.checkNotNullParameter(K.a(com.quizlet.shared.persistence.db.persistencedatabase.c.class), "<this>");
                com.quizlet.shared.persistence.db.persistencedatabase.b schema = com.quizlet.shared.persistence.db.persistencedatabase.b.a;
                Intrinsics.checkNotNullParameter(schema, "schema");
                Intrinsics.checkNotNullParameter("quizlet_shared.sqlite", "name");
                com.google.android.material.shape.e factory = new com.google.android.material.shape.e(5);
                d callback = new d(new app.cash.sqldelight.db.a[0]);
                Intrinsics.checkNotNullParameter(schema, "schema");
                Context context = databaseDriverFactory.a;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(factory, "factory");
                Intrinsics.checkNotNullParameter(callback, "callback");
                Intrinsics.checkNotNullParameter(context, "context");
                androidx.sqlite.db.c cVar = new androidx.sqlite.db.c(context);
                Intrinsics.checkNotNullParameter(callback, "callback");
                cVar.c = callback;
                cVar.b = "quizlet_shared.sqlite";
                cVar.d = false;
                i driver = new i(factory.d(cVar.a()), null, 20);
                Intrinsics.checkNotNullParameter(driver, "driver");
                Intrinsics.checkNotNullParameter(K.a(com.quizlet.shared.persistence.db.persistencedatabase.c.class), "<this>");
                app.cash.sqldelight.db.a[] aVarArr = (app.cash.sqldelight.db.a[]) Arrays.copyOf(com.quizlet.shared.persistence.db.b.a, 0);
                int iIntValue = ((Number) driver.f(null, "PRAGMA user_version", com.quizlet.shared.persistence.db.a.b, 0, null).b).intValue();
                if (iIntValue == 0) {
                    schema.getClass();
                    Intrinsics.checkNotNullParameter(driver, "driver");
                    driver.a(null, "CREATE TABLE dbStudiableMetadata (\n    studiableMetadataType INTEGER NOT NULL,\n    studiableContainerId INTEGER NOT NULL,\n    studiableContainerType INTEGER NOT NULL,\n    model TEXT,\n    PRIMARY KEY (studiableMetadataType, studiableContainerId, studiableContainerType)\n)", null);
                    app.cash.sqldelight.db.d.a.getClass();
                    new app.cash.sqldelight.db.c(app.cash.sqldelight.db.b.b);
                } else {
                    long j = iIntValue;
                    if (j < 2) {
                        schema.a(driver, j, 2L, (app.cash.sqldelight.db.a[]) Arrays.copyOf(aVarArr, aVarArr.length));
                        driver = driver;
                    }
                }
                driver.a(null, "PRAGMA user_version=2", null);
                com.quizlet.quizletandroid.ui.joincontenttofolder.i studiableMetadataTypeAdapter = new com.quizlet.quizletandroid.ui.joincontenttofolder.i(s.values());
                com.quizlet.quizletandroid.ui.joincontenttofolder.i studiableContainerTypeAdapter = new com.quizlet.quizletandroid.ui.joincontenttofolder.i(assistantMode.refactored.enums.j.values());
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c modelAdapter = new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(R1.a(f.Companion.serializer()));
                Intrinsics.checkNotNullParameter(studiableMetadataTypeAdapter, "studiableMetadataTypeAdapter");
                Intrinsics.checkNotNullParameter(studiableContainerTypeAdapter, "studiableContainerTypeAdapter");
                Intrinsics.checkNotNullParameter(modelAdapter, "modelAdapter");
                com.quizlet.data.repository.login.a dbStudiableMetadataAdapter = new com.quizlet.data.repository.login.a();
                dbStudiableMetadataAdapter.a = studiableMetadataTypeAdapter;
                dbStudiableMetadataAdapter.b = studiableContainerTypeAdapter;
                dbStudiableMetadataAdapter.c = modelAdapter;
                Intrinsics.checkNotNullParameter(driver, "driver");
                Intrinsics.checkNotNullParameter(dbStudiableMetadataAdapter, "dbStudiableMetadataAdapter");
                Intrinsics.checkNotNullParameter(K.a(com.quizlet.shared.persistence.db.persistencedatabase.c.class), "<this>");
                Intrinsics.checkNotNullParameter(driver, "driver");
                Intrinsics.checkNotNullParameter(dbStudiableMetadataAdapter, "dbStudiableMetadataAdapter");
                return new com.quizlet.shared.persistence.db.persistencedatabase.c(driver, dbStudiableMetadataAdapter);
            default:
                org.koin.core.scope.a aVar2 = (org.koin.core.scope.a) obj;
                return new e((com.quizlet.shared.persistence.db.persistencedatabase.c) aVar2.a(null, B.q(aVar2, "$this$single", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.persistence.db.persistencedatabase.c.class), null));
        }
    }
}
