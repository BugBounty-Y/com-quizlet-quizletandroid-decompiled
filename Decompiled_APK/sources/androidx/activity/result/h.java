package androidx.activity.result;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import androidx.lifecycle.B;
import androidx.lifecycle.C;
import androidx.lifecycle.H;
import androidx.lifecycle.J;
import androidx.lifecycle.L;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3197l6;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.l;

/* loaded from: classes.dex */
public abstract class h {
    public final LinkedHashMap a = new LinkedHashMap();
    public final LinkedHashMap b = new LinkedHashMap();
    public final LinkedHashMap c = new LinkedHashMap();
    public final ArrayList d = new ArrayList();
    public final transient LinkedHashMap e = new LinkedHashMap();
    public final LinkedHashMap f = new LinkedHashMap();
    public final Bundle g = new Bundle();

    public final boolean a(int i, int i2, Intent intent) {
        String str = (String) this.a.get(Integer.valueOf(i));
        if (str == null) {
            return false;
        }
        d dVar = (d) this.e.get(str);
        if ((dVar != null ? dVar.a : null) != null) {
            ArrayList arrayList = this.d;
            if (arrayList.contains(str)) {
                dVar.a.a(dVar.b.c(i2, intent));
                arrayList.remove(str);
                return true;
            }
        }
        this.f.remove(str);
        this.g.putParcelable(str, new ActivityResult(i2, intent));
        return true;
    }

    public abstract void b(int i, androidx.activity.result.contract.a aVar, Object obj);

    public final g c(String key, androidx.activity.result.contract.a contract, a callback) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(contract, "contract");
        Intrinsics.checkNotNullParameter(callback, "callback");
        e(key);
        this.e.put(key, new d(contract, callback));
        LinkedHashMap linkedHashMap = this.f;
        if (linkedHashMap.containsKey(key)) {
            Object obj = linkedHashMap.get(key);
            linkedHashMap.remove(key);
            callback.a(obj);
        }
        Bundle bundle = this.g;
        ActivityResult activityResult = (ActivityResult) AbstractC3197l6.a(bundle, key);
        if (activityResult != null) {
            bundle.remove(key);
            callback.a(contract.c(activityResult.a, activityResult.b));
        }
        return new g(this, key, contract, 1);
    }

    public final g d(String key, J lifecycleOwner, androidx.activity.result.contract.a contract, a callback) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(lifecycleOwner, "lifecycleOwner");
        Intrinsics.checkNotNullParameter(contract, "contract");
        Intrinsics.checkNotNullParameter(callback, "callback");
        C lifecycle = lifecycleOwner.getLifecycle();
        L l = (L) lifecycle;
        if (l.d.a(B.d)) {
            throw new IllegalStateException(("LifecycleOwner " + lifecycleOwner + " is attempting to register while current state is " + l.d + ". LifecycleOwners must call register before they are STARTED.").toString());
        }
        e(key);
        LinkedHashMap linkedHashMap = this.c;
        e eVar = (e) linkedHashMap.get(key);
        if (eVar == null) {
            eVar = new e(lifecycle);
        }
        c observer = new c(this, key, callback, contract, 0);
        Intrinsics.checkNotNullParameter(observer, "observer");
        eVar.a.a(observer);
        eVar.b.add(observer);
        linkedHashMap.put(key, eVar);
        return new g(this, key, contract, 0);
    }

    public final void e(String str) {
        LinkedHashMap linkedHashMap = this.b;
        if (((Integer) linkedHashMap.get(str)) != null) {
            return;
        }
        f nextFunction = f.a;
        Intrinsics.checkNotNullParameter(nextFunction, "nextFunction");
        kotlin.sequences.g gVar = new kotlin.sequences.g(nextFunction, new l(1));
        Intrinsics.checkNotNullParameter(gVar, "<this>");
        Iterator it2 = new kotlin.sequences.a(gVar).iterator();
        while (it2.hasNext()) {
            Number number = (Number) it2.next();
            int iIntValue = number.intValue();
            LinkedHashMap linkedHashMap2 = this.a;
            if (!linkedHashMap2.containsKey(Integer.valueOf(iIntValue))) {
                int iIntValue2 = number.intValue();
                linkedHashMap2.put(Integer.valueOf(iIntValue2), str);
                linkedHashMap.put(str, Integer.valueOf(iIntValue2));
                return;
            }
        }
        throw new NoSuchElementException("Sequence contains no element matching the predicate.");
    }

    public final void f(String key) {
        Integer num;
        Intrinsics.checkNotNullParameter(key, "key");
        if (!this.d.contains(key) && (num = (Integer) this.b.remove(key)) != null) {
            this.a.remove(num);
        }
        this.e.remove(key);
        LinkedHashMap linkedHashMap = this.f;
        if (linkedHashMap.containsKey(key)) {
            StringBuilder sbY = android.support.v4.media.session.a.y("Dropping pending result for request ", key, ": ");
            sbY.append(linkedHashMap.get(key));
            Log.w("ActivityResultRegistry", sbY.toString());
            linkedHashMap.remove(key);
        }
        Bundle bundle = this.g;
        if (bundle.containsKey(key)) {
            Log.w("ActivityResultRegistry", "Dropping pending result for request " + key + ": " + ((ActivityResult) AbstractC3197l6.a(bundle, key)));
            bundle.remove(key);
        }
        LinkedHashMap linkedHashMap2 = this.c;
        e eVar = (e) linkedHashMap2.get(key);
        if (eVar != null) {
            ArrayList arrayList = eVar.b;
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                eVar.a.b((H) it2.next());
            }
            arrayList.clear();
            linkedHashMap2.remove(key);
        }
    }
}
