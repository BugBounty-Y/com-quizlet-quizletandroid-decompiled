package com.google.android.gms.internal.mlkit_vision_barcode;

import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.infra.models.Creator;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class C6 {
    public static final androidx.lifecycle.X a(List inputs, Function1 combine) {
        Intrinsics.checkNotNullParameter(inputs, "inputs");
        Intrinsics.checkNotNullParameter(combine, "combine");
        androidx.lifecycle.X x = new androidx.lifecycle.X(0);
        int size = inputs.size();
        ArrayList arrayList = new ArrayList(size);
        int i = 0;
        for (int i2 = 0; i2 < size; i2++) {
            arrayList.add(null);
        }
        for (Object obj : inputs) {
            int i3 = i + 1;
            if (i < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            x.m((androidx.lifecycle.T) obj, new com.quizlet.ads.ui.fragments.c(new com.quizlet.viewmodel.livedata.a(x, arrayList, i, combine)));
            i = i3;
        }
        return x;
    }

    public static final Creator b(DBUser dBUser) {
        String username;
        Intrinsics.checkNotNullParameter(dBUser, "<this>");
        if (dBUser.getUsername() != null) {
            username = dBUser.getUsername();
        } else {
            timber.log.c.a.o("Null username for user with ID (" + dBUser.getId() + ") and DELETED (" + dBUser.getDeleted() + ")", new Object[0]);
            username = "";
        }
        long id = dBUser.getId();
        String str = username == null ? "" : username;
        String imageUrl = dBUser.getImageUrl();
        return new Creator(dBUser.getCreatorBadgeText(), id, str, imageUrl == null ? "" : imageUrl, dBUser.getIsVerified(), dBUser.getDeleted());
    }
}
