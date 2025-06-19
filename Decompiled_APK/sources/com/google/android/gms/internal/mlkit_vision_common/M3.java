package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.ads.Mu;
import com.quizlet.features.universaluploadflow.UniversalUploadFlowActivity;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class M3 {
    public static Intent a(Context context, com.quizlet.data.model.m2 source) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(source, "source");
        Intent intent = new Intent(context, (Class<?>) UniversalUploadFlowActivity.class);
        intent.putExtra("source", source);
        return intent;
    }

    public static boolean b(Mu mu, Collection collection) {
        collection.getClass();
        if (collection instanceof com.google.android.gms.internal.mlkit_vision_barcode.A) {
            collection = ((com.google.android.gms.internal.mlkit_vision_barcode.A) collection).zza();
        }
        boolean zRemove = false;
        if (!(collection instanceof Set) || collection.size() <= mu.size()) {
            Iterator it2 = collection.iterator();
            while (it2.hasNext()) {
                zRemove |= mu.remove(it2.next());
            }
            return zRemove;
        }
        Iterator<E> it3 = mu.iterator();
        collection.getClass();
        while (it3.hasNext()) {
            if (collection.contains(it3.next())) {
                it3.remove();
                zRemove = true;
            }
        }
        return zRemove;
    }
}
