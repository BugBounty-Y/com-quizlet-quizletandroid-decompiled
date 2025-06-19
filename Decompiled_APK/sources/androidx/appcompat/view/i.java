package androidx.appcompat.view;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.util.AttributeSet;
import android.util.Log;
import android.util.Xml;
import android.view.InflateException;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.SubMenu;
import androidx.appcompat.widget.AbstractC0102o0;
import androidx.core.view.AbstractC1040c;
import com.quizlet.db.data.models.persisted.DBGroup;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import org.xmlpull.v1.XmlPullParserException;

/* loaded from: classes.dex */
public class i extends MenuInflater {
    public static final Class[] e;
    public static final Class[] f;
    public final Object[] a;
    public final Object[] b;
    public final Context c;
    public Object d;

    static {
        Class[] clsArr = {Context.class};
        e = clsArr;
        f = clsArr;
    }

    public i(Context context) {
        super(context);
        this.c = context;
        Object[] objArr = {context};
        this.a = objArr;
        this.b = objArr;
    }

    public static Object a(Object obj) {
        return (!(obj instanceof Activity) && (obj instanceof ContextWrapper)) ? a(((ContextWrapper) obj).getBaseContext()) : obj;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r4v59 */
    public final void b(XmlResourceParser xmlResourceParser, AttributeSet attributeSet, Menu menu) throws XmlPullParserException, IllegalAccessException, IOException, IllegalArgumentException, InvocationTargetException {
        ?? r4;
        int i;
        XmlResourceParser xmlResourceParser2;
        boolean z;
        ColorStateList colorStateList;
        h hVar = new h(this, menu);
        int eventType = xmlResourceParser.getEventType();
        while (true) {
            r4 = 1;
            i = 2;
            if (eventType == 2) {
                String name = xmlResourceParser.getName();
                if (!name.equals("menu")) {
                    throw new RuntimeException("Expecting menu, got ".concat(name));
                }
                eventType = xmlResourceParser.next();
            } else {
                eventType = xmlResourceParser.next();
                if (eventType == 1) {
                    break;
                }
            }
        }
        boolean z2 = false;
        boolean z3 = false;
        String str = null;
        while (!z2) {
            if (eventType == r4) {
                throw new RuntimeException("Unexpected end of document");
            }
            if (eventType != i) {
                if (eventType != 3) {
                    xmlResourceParser2 = xmlResourceParser;
                    z = r4;
                } else {
                    String name2 = xmlResourceParser.getName();
                    if (z3 && name2.equals(str)) {
                        xmlResourceParser2 = xmlResourceParser;
                        z = r4;
                        z3 = false;
                        str = null;
                    } else {
                        if (name2.equals(DBGroup.TABLE_NAME)) {
                            hVar.b = 0;
                            hVar.c = 0;
                            hVar.d = 0;
                            hVar.e = 0;
                            hVar.f = r4;
                            hVar.g = r4;
                        } else if (name2.equals("item")) {
                            if (!hVar.h) {
                                AbstractC1040c abstractC1040c = hVar.z;
                                if (abstractC1040c == null || !abstractC1040c.a()) {
                                    hVar.h = r4;
                                    hVar.b(hVar.a.add(hVar.b, hVar.i, hVar.j, hVar.k));
                                } else {
                                    hVar.h = r4;
                                    hVar.b(hVar.a.addSubMenu(hVar.b, hVar.i, hVar.j, hVar.k).getItem());
                                }
                            }
                        } else if (name2.equals("menu")) {
                            xmlResourceParser2 = xmlResourceParser;
                            z = r4;
                            z2 = z;
                        }
                        xmlResourceParser2 = xmlResourceParser;
                        z = r4;
                    }
                }
                eventType = xmlResourceParser2.next();
                r4 = z;
                i = 2;
                z3 = z3;
            } else {
                if (!z3) {
                    String name3 = xmlResourceParser.getName();
                    boolean zEquals = name3.equals(DBGroup.TABLE_NAME);
                    i iVar = hVar.E;
                    if (zEquals) {
                        TypedArray typedArrayObtainStyledAttributes = iVar.c.obtainStyledAttributes(attributeSet, androidx.appcompat.a.q);
                        hVar.b = typedArrayObtainStyledAttributes.getResourceId(r4, 0);
                        hVar.c = typedArrayObtainStyledAttributes.getInt(3, 0);
                        hVar.d = typedArrayObtainStyledAttributes.getInt(4, 0);
                        hVar.e = typedArrayObtainStyledAttributes.getInt(5, 0);
                        hVar.f = typedArrayObtainStyledAttributes.getBoolean(2, r4);
                        hVar.g = typedArrayObtainStyledAttributes.getBoolean(0, r4);
                        typedArrayObtainStyledAttributes.recycle();
                    } else {
                        if (name3.equals("item")) {
                            com.quizlet.data.repository.classfolder.e eVarL = com.quizlet.data.repository.classfolder.e.l(iVar.c, attributeSet, androidx.appcompat.a.r);
                            TypedArray typedArray = (TypedArray) eVarL.c;
                            hVar.i = typedArray.getResourceId(2, 0);
                            hVar.j = (typedArray.getInt(5, hVar.c) & (-65536)) | (typedArray.getInt(6, hVar.d) & 65535);
                            hVar.k = typedArray.getText(7);
                            hVar.l = typedArray.getText(8);
                            hVar.m = typedArray.getResourceId(0, 0);
                            String string = typedArray.getString(9);
                            hVar.n = string == null ? (char) 0 : string.charAt(0);
                            hVar.o = typedArray.getInt(16, 4096);
                            String string2 = typedArray.getString(10);
                            hVar.p = string2 == null ? (char) 0 : string2.charAt(0);
                            hVar.q = typedArray.getInt(20, 4096);
                            if (typedArray.hasValue(11)) {
                                hVar.r = typedArray.getBoolean(11, false) ? 1 : 0;
                            } else {
                                hVar.r = hVar.e;
                            }
                            hVar.s = typedArray.getBoolean(3, false);
                            hVar.t = typedArray.getBoolean(4, hVar.f);
                            hVar.u = typedArray.getBoolean(1, hVar.g);
                            hVar.v = typedArray.getInt(21, -1);
                            hVar.y = typedArray.getString(12);
                            hVar.w = typedArray.getResourceId(13, 0);
                            hVar.x = typedArray.getString(15);
                            String string3 = typedArray.getString(14);
                            boolean z4 = string3 != null;
                            if (z4 && hVar.w == 0 && hVar.x == null) {
                                hVar.z = (AbstractC1040c) hVar.a(string3, f, iVar.b);
                            } else {
                                if (z4) {
                                    Log.w("SupportMenuInflater", "Ignoring attribute 'actionProviderClass'. Action view already specified.");
                                }
                                hVar.z = null;
                            }
                            hVar.A = typedArray.getText(17);
                            hVar.B = typedArray.getText(22);
                            if (typedArray.hasValue(19)) {
                                hVar.D = AbstractC0102o0.c(typedArray.getInt(19, -1), hVar.D);
                                colorStateList = null;
                            } else {
                                colorStateList = null;
                                hVar.D = null;
                            }
                            if (typedArray.hasValue(18)) {
                                hVar.C = eVarL.e(18);
                            } else {
                                hVar.C = colorStateList;
                            }
                            eVarL.n();
                            hVar.h = false;
                            xmlResourceParser2 = xmlResourceParser;
                            z = true;
                        } else if (name3.equals("menu")) {
                            z = true;
                            hVar.h = true;
                            SubMenu subMenuAddSubMenu = hVar.a.addSubMenu(hVar.b, hVar.i, hVar.j, hVar.k);
                            hVar.b(subMenuAddSubMenu.getItem());
                            xmlResourceParser2 = xmlResourceParser;
                            b(xmlResourceParser2, attributeSet, subMenuAddSubMenu);
                        } else {
                            xmlResourceParser2 = xmlResourceParser;
                            z = true;
                            str = name3;
                            z3 = true;
                        }
                        eventType = xmlResourceParser2.next();
                        r4 = z;
                        i = 2;
                        z3 = z3;
                    }
                }
                xmlResourceParser2 = xmlResourceParser;
                z = r4;
            }
            eventType = xmlResourceParser2.next();
            r4 = z;
            i = 2;
            z3 = z3;
        }
    }

    @Override // android.view.MenuInflater
    public final void inflate(int i, Menu menu) {
        if (!(menu instanceof androidx.appcompat.view.menu.n)) {
            super.inflate(i, menu);
            return;
        }
        XmlResourceParser layout = null;
        boolean z = false;
        try {
            try {
                layout = this.c.getResources().getLayout(i);
                AttributeSet attributeSetAsAttributeSet = Xml.asAttributeSet(layout);
                if (menu instanceof androidx.appcompat.view.menu.n) {
                    androidx.appcompat.view.menu.n nVar = (androidx.appcompat.view.menu.n) menu;
                    if (!nVar.p) {
                        nVar.w();
                        z = true;
                    }
                }
                b(layout, attributeSetAsAttributeSet, menu);
                if (z) {
                    ((androidx.appcompat.view.menu.n) menu).v();
                }
                layout.close();
            } catch (IOException e2) {
                throw new InflateException("Error inflating menu XML", e2);
            } catch (XmlPullParserException e3) {
                throw new InflateException("Error inflating menu XML", e3);
            }
        } catch (Throwable th) {
            if (z) {
                ((androidx.appcompat.view.menu.n) menu).v();
            }
            if (layout != null) {
                layout.close();
            }
            throw th;
        }
    }
}
