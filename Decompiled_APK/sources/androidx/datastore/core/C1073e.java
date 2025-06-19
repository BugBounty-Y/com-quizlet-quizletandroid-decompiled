package androidx.datastore.core;

import com.google.android.gms.internal.mlkit_vision_barcode.L6;
import java.io.Serializable;
import java.util.Iterator;

/* renamed from: androidx.datastore.core.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1073e extends kotlin.coroutines.jvm.internal.c {
    public Serializable j;
    public Iterator k;
    public /* synthetic */ Object l;
    public int m;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.m |= Integer.MIN_VALUE;
        return L6.a(null, null, this);
    }
}
