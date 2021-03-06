/*
 * Copyright (c) 2008-2017 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.haulmont.cuba.web.gui.components.imageresources;

import com.haulmont.bali.util.Preconditions;
import com.haulmont.cuba.gui.components.Image;
import com.haulmont.cuba.web.controllers.ControllerUtils;
import com.haulmont.cuba.web.gui.components.WebImage;
import com.vaadin.server.ExternalResource;

import java.net.MalformedURLException;
import java.net.URL;

public class WebRelativePathImageResource extends WebImage.WebAbstractImageResource implements WebImageResource, Image.RelativePathImageResource {

    protected String path;

    @Override
    public Image.RelativePathImageResource setPath(String path) {
        Preconditions.checkNotNullArgument(path);

        this.path = path;
        hasSource = true;

        fireResourceUpdateEvent();

        return this;
    }

    @Override
    public String getPath() {
        return path;
    }

    @Override
    protected void createResource() {
        try {
            URL context = new URL(ControllerUtils.getLocationWithoutParams());
            resource = new ExternalResource(new URL(context, path));
        } catch (MalformedURLException e) {
            throw new RuntimeException("Can't create RelativePathImageResource", e);
        }
    }
}