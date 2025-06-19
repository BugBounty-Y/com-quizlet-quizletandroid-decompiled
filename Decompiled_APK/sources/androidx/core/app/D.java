package androidx.core.app;

import android.app.Notification;
import android.os.Build;
import android.os.Bundle;
import com.quizlet.db.data.models.base.AssociationNames;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class D {
    public final String a;
    public final long b;
    public final Q c;
    public final Bundle d = new Bundle();

    public D(String str, long j, Q q) {
        this.a = str;
        this.b = j;
        this.c = q;
    }

    public static Bundle[] a(ArrayList arrayList) {
        Bundle[] bundleArr = new Bundle[arrayList.size()];
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            D d = (D) arrayList.get(i);
            d.getClass();
            Bundle bundle = new Bundle();
            String str = d.a;
            if (str != null) {
                bundle.putCharSequence("text", str);
            }
            bundle.putLong("time", d.b);
            Q q = d.c;
            if (q != null) {
                bundle.putCharSequence("sender", q.a);
                if (Build.VERSION.SDK_INT >= 28) {
                    bundle.putParcelable("sender_person", C.a(AbstractC1027n.g(q)));
                } else {
                    bundle.putBundle(AssociationNames.PERSON, q.a());
                }
            }
            Bundle bundle2 = d.d;
            if (bundle2 != null) {
                bundle.putBundle("extras", bundle2);
            }
            bundleArr[i] = bundle;
        }
        return bundleArr;
    }

    public final Notification.MessagingStyle.Message b() {
        int i = Build.VERSION.SDK_INT;
        long j = this.b;
        String str = this.a;
        Q q = this.c;
        if (i >= 28) {
            return C.b(str, j, q != null ? AbstractC1027n.g(q) : null);
        }
        return B.a(str, j, q != null ? q.a : null);
    }
}
