package com.quizlet.db.data.models.base;

import androidx.camera.camera2.internal.a0;
import java.util.Comparator;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class Comparators {

    @NotNull
    public static final Comparators INSTANCE = new Comparators();

    @NotNull
    public static final Comparator<DBModel> DEFAULT_ASC = new a0(19);

    @NotNull
    public static final Comparator<DBModel> DEFAULT_DESC = new a0(20);

    private Comparators() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int DEFAULT_ASC$lambda$0(DBModel dBModel, DBModel dBModel2) {
        Intrinsics.d(dBModel);
        Intrinsics.d(dBModel2);
        return dBModel.compare(dBModel, dBModel2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int DEFAULT_DESC$lambda$1(DBModel dBModel, DBModel dBModel2) {
        Intrinsics.d(dBModel);
        Intrinsics.d(dBModel2);
        return dBModel.compare(dBModel, dBModel2) * (-1);
    }
}
