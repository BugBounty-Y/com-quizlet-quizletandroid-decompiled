package coil3.map;

import android.content.Context;
import android.content.res.Resources;
import android.net.Uri;
import coil3.n;
import coil3.request.m;
import coil3.y;
import java.io.File;
import okio.x;

/* loaded from: classes.dex */
public final class a {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public final y a(Object obj, m mVar) {
        switch (this.a) {
            case 0:
                return n.i(((Uri) obj).toString());
            case 1:
                return n.a(((File) obj).getPath());
            case 2:
                return n.a(((x) obj).a.s());
            case 3:
                Context context = mVar.a;
                int iIntValue = ((Number) obj).intValue();
                try {
                    if (context.getResources().getResourceEntryName(iIntValue) != null) {
                        return n.i("android.resource://" + context.getPackageName() + '/' + iIntValue);
                    }
                } catch (Resources.NotFoundException unused) {
                }
                return null;
            default:
                return n.i((String) obj);
        }
    }
}
