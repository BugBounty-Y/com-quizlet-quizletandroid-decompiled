package androidx.fragment.app;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.fragment.app.strictmode.FragmentTagUsageViolation;
import com.quizlet.db.data.models.base.AssociationNames;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Q implements LayoutInflater.Factory2 {
    public final AbstractC1136h0 a;

    public Q(AbstractC1136h0 abstractC1136h0) {
        this.a = abstractC1136h0;
    }

    @Override // android.view.LayoutInflater.Factory
    public final View onCreateView(String str, Context context, AttributeSet attributeSet) {
        return onCreateView(null, str, context, attributeSet);
    }

    @Override // android.view.LayoutInflater.Factory2
    public final View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        boolean zIsAssignableFrom;
        o0 o0VarH;
        boolean zEquals = FragmentContainerView.class.getName().equals(str);
        AbstractC1136h0 abstractC1136h0 = this.a;
        if (zEquals) {
            return new FragmentContainerView(context, attributeSet, abstractC1136h0);
        }
        if ("fragment".equals(str)) {
            String attributeValue = attributeSet.getAttributeValue(null, AssociationNames.CLASS);
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, androidx.fragment.a.a);
            if (attributeValue == null) {
                attributeValue = typedArrayObtainStyledAttributes.getString(0);
            }
            int resourceId = typedArrayObtainStyledAttributes.getResourceId(1, -1);
            String string = typedArrayObtainStyledAttributes.getString(2);
            typedArrayObtainStyledAttributes.recycle();
            if (attributeValue != null) {
                try {
                    zIsAssignableFrom = Fragment.class.isAssignableFrom(N.b(context.getClassLoader(), attributeValue));
                } catch (ClassNotFoundException unused) {
                    zIsAssignableFrom = false;
                }
                if (zIsAssignableFrom) {
                    int id = view != null ? view.getId() : 0;
                    if (id == -1 && resourceId == -1 && string == null) {
                        throw new IllegalArgumentException(attributeSet.getPositionDescription() + ": Must specify unique android:id, android:tag, or have a parent with an id for " + attributeValue);
                    }
                    Fragment fragment = resourceId != -1 ? abstractC1136h0.D(resourceId) : null;
                    if (fragment == null && string != null) {
                        fragment = abstractC1136h0.E(string);
                    }
                    if (fragment == null && id != -1) {
                        fragment = abstractC1136h0.D(id);
                    }
                    if (fragment == null) {
                        N nL = abstractC1136h0.L();
                        context.getClassLoader();
                        fragment = nL.a(attributeValue);
                        fragment.mFromLayout = true;
                        fragment.mFragmentId = resourceId != 0 ? resourceId : id;
                        fragment.mContainerId = id;
                        fragment.mTag = string;
                        fragment.mInLayout = true;
                        fragment.mFragmentManager = abstractC1136h0;
                        O o = abstractC1136h0.x;
                        fragment.mHost = o;
                        fragment.onInflate((Context) o.b, attributeSet, fragment.mSavedFragmentState);
                        o0VarH = abstractC1136h0.a(fragment);
                        if (AbstractC1136h0.N(2)) {
                            fragment.toString();
                            Integer.toHexString(resourceId);
                        }
                    } else {
                        if (fragment.mInLayout) {
                            throw new IllegalArgumentException(attributeSet.getPositionDescription() + ": Duplicate id 0x" + Integer.toHexString(resourceId) + ", tag " + string + ", or parent id 0x" + Integer.toHexString(id) + " with another fragment for " + attributeValue);
                        }
                        fragment.mInLayout = true;
                        fragment.mFragmentManager = abstractC1136h0;
                        O o2 = abstractC1136h0.x;
                        fragment.mHost = o2;
                        fragment.onInflate((Context) o2.b, attributeSet, fragment.mSavedFragmentState);
                        o0VarH = abstractC1136h0.h(fragment);
                        if (AbstractC1136h0.N(2)) {
                            fragment.toString();
                            Integer.toHexString(resourceId);
                        }
                    }
                    ViewGroup viewGroup = (ViewGroup) view;
                    androidx.fragment.app.strictmode.b bVar = androidx.fragment.app.strictmode.c.a;
                    Intrinsics.checkNotNullParameter(fragment, "fragment");
                    androidx.fragment.app.strictmode.c.b(new FragmentTagUsageViolation(fragment, viewGroup));
                    androidx.fragment.app.strictmode.c.a(fragment).a.contains(androidx.fragment.app.strictmode.a.b);
                    fragment.mContainer = viewGroup;
                    o0VarH.i();
                    o0VarH.h();
                    View view2 = fragment.mView;
                    if (view2 == null) {
                        throw new IllegalStateException(android.support.v4.media.session.a.B("Fragment ", attributeValue, " did not create a view."));
                    }
                    if (resourceId != 0) {
                        view2.setId(resourceId);
                    }
                    if (fragment.mView.getTag() == null) {
                        fragment.mView.setTag(string);
                    }
                    fragment.mView.addOnAttachStateChangeListener(new P(this, o0VarH));
                    return fragment.mView;
                }
            }
        }
        return null;
    }
}
