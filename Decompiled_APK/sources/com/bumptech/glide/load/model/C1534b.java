package com.bumptech.glide.load.model;

import android.content.Context;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.net.Uri;
import android.util.Log;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.bumptech.glide.load.model.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1534b implements r {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ C1534b(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // com.bumptech.glide.load.model.r
    public final boolean a(Object obj) {
        switch (this.a) {
            case 0:
                Uri uri = (Uri) obj;
                if (!"file".equals(uri.getScheme()) || uri.getPathSegments().isEmpty() || !"android_asset".equals(uri.getPathSegments().get(0))) {
                }
                break;
            case 1:
                break;
            case 2:
                Iterator it2 = ((ArrayList) this.c).iterator();
                while (it2.hasNext()) {
                    if (((r) it2.next()).a(obj)) {
                        break;
                    }
                }
                break;
            case 3:
                break;
            default:
                Uri uri2 = (Uri) obj;
                if (!"android.resource".equals(uri2.getScheme()) || !((Context) this.c).getPackageName().equals(uri2.getAuthority())) {
                }
                break;
        }
        return true;
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) throws NumberFormatException {
        com.bumptech.glide.load.data.k kVar;
        q qVarB;
        Uri uri;
        switch (this.a) {
            case 0:
                Uri uri2 = (Uri) obj;
                String strSubstring = uri2.toString().substring(22);
                com.bumptech.glide.signature.b bVar = new com.bumptech.glide.signature.b(uri2);
                Object obj2 = this.b;
                AssetManager assetManager = (AssetManager) this.c;
                switch (((C1533a) obj2).a) {
                    case 0:
                        kVar = new com.bumptech.glide.load.data.k(assetManager, strSubstring, 0);
                        break;
                    default:
                        kVar = new com.bumptech.glide.load.data.k(assetManager, strSubstring, 1);
                        break;
                }
                return new q(bVar, kVar);
            case 1:
                Integer num = (Integer) obj;
                Resources.Theme theme = (Resources.Theme) hVar.c(com.bumptech.glide.load.resource.drawable.c.b);
                return new q(new com.bumptech.glide.signature.b(num), new f(theme, theme != null ? theme.getResources() : ((Context) this.c).getResources(), (C1537e) this.b, num.intValue()));
            case 2:
                ArrayList arrayList = (ArrayList) this.c;
                int size = arrayList.size();
                ArrayList arrayList2 = new ArrayList(size);
                com.bumptech.glide.load.e eVar = null;
                for (int i3 = 0; i3 < size; i3++) {
                    r rVar = (r) arrayList.get(i3);
                    if (rVar.a(obj) && (qVarB = rVar.b(obj, i, i2, hVar)) != null) {
                        arrayList2.add(qVarB.c);
                        eVar = qVarB.a;
                    }
                }
                if (arrayList2.isEmpty() || eVar == null) {
                    return null;
                }
                return new q(eVar, new v(arrayList2, (com.quizlet.data.repository.course.membership.c) this.b));
            case 3:
                Integer num2 = (Integer) obj;
                Resources resources = (Resources) this.b;
                try {
                    uri = Uri.parse("android.resource://" + resources.getResourcePackageName(num2.intValue()) + '/' + resources.getResourceTypeName(num2.intValue()) + '/' + resources.getResourceEntryName(num2.intValue()));
                } catch (Resources.NotFoundException e) {
                    if (Log.isLoggable("ResourceLoader", 5)) {
                        Log.w("ResourceLoader", "Received invalid resource id: " + num2, e);
                    }
                    uri = null;
                }
                if (uri == null) {
                    return null;
                }
                return ((r) this.c).b(uri, i, i2, hVar);
            default:
                Uri uri3 = (Uri) obj;
                List<String> pathSegments = uri3.getPathSegments();
                int size2 = pathSegments.size();
                r rVar2 = (r) this.b;
                q qVarB2 = null;
                if (size2 == 1) {
                    try {
                        int i4 = Integer.parseInt(uri3.getPathSegments().get(0));
                        if (i4 != 0) {
                            qVarB2 = rVar2.b(Integer.valueOf(i4), i, i2, hVar);
                        } else if (Log.isLoggable("ResourceUriLoader", 5)) {
                            Log.w("ResourceUriLoader", "Failed to parse a valid non-0 resource id from: " + uri3);
                        }
                        return qVarB2;
                    } catch (NumberFormatException e2) {
                        if (!Log.isLoggable("ResourceUriLoader", 5)) {
                            return qVarB2;
                        }
                        Log.w("ResourceUriLoader", "Failed to parse resource id from: " + uri3, e2);
                        return qVarB2;
                    }
                }
                if (pathSegments.size() != 2) {
                    if (!Log.isLoggable("ResourceUriLoader", 5)) {
                        return null;
                    }
                    Log.w("ResourceUriLoader", "Failed to parse resource uri: " + uri3);
                    return null;
                }
                List<String> pathSegments2 = uri3.getPathSegments();
                String str = pathSegments2.get(0);
                String str2 = pathSegments2.get(1);
                Context context = (Context) this.c;
                int identifier = context.getResources().getIdentifier(str2, str, context.getPackageName());
                if (identifier != 0) {
                    return rVar2.b(Integer.valueOf(identifier), i, i2, hVar);
                }
                if (!Log.isLoggable("ResourceUriLoader", 5)) {
                    return null;
                }
                Log.w("ResourceUriLoader", "Failed to find resource id for: " + uri3);
                return null;
        }
    }

    public String toString() {
        switch (this.a) {
            case 2:
                return "MultiModelLoader{modelLoaders=" + Arrays.toString(((ArrayList) this.c).toArray()) + '}';
            default:
                return super.toString();
        }
    }

    public C1534b(Resources resources, r rVar) {
        this.a = 3;
        this.b = resources;
        this.c = rVar;
    }

    public C1534b(Context context, C1537e c1537e) {
        this.a = 1;
        this.c = context.getApplicationContext();
        this.b = c1537e;
    }

    public C1534b(Context context, r rVar) {
        this.a = 4;
        this.c = context.getApplicationContext();
        this.b = rVar;
    }
}
