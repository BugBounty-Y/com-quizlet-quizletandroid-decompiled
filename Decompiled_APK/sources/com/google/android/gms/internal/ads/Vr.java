package com.google.android.gms.internal.ads;

import android.view.View;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class Vr {
    public static final Pattern b = Pattern.compile("^[a-zA-Z0-9 ]+$");
    public final ArrayList a = new ArrayList();

    public final void a(View view, Jr jr) {
        Ur ur;
        if (view == null) {
            throw new IllegalArgumentException("FriendlyObstruction is null");
        }
        if (!b.matcher("Ad overlay").matches()) {
            throw new IllegalArgumentException("FriendlyObstruction has detailed reason that contains characters not in [a-z][A-Z][0-9] or space");
        }
        ArrayList arrayList = this.a;
        Iterator it2 = arrayList.iterator();
        while (true) {
            if (!it2.hasNext()) {
                ur = null;
                break;
            } else {
                ur = (Ur) it2.next();
                if (ur.a.get() == view) {
                    break;
                }
            }
        }
        if (ur == null) {
            arrayList.add(new Ur(view, jr));
        }
    }
}
