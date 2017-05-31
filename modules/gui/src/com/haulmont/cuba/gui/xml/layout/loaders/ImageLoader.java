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

package com.haulmont.cuba.gui.xml.layout.loaders;

import com.haulmont.cuba.gui.GuiDevelopmentException;
import com.haulmont.cuba.gui.components.Image;
import com.haulmont.cuba.gui.data.Datasource;
import org.apache.commons.lang.StringUtils;
import org.dom4j.Element;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

public class ImageLoader extends AbstractComponentLoader<Image> {

    @Override
    public void createComponent() {
        resultComponent = (Image) factory.createComponent(Image.NAME);
        loadId(resultComponent, element);
    }

    @Override
    public void loadComponent() {
        loadWidth(resultComponent, element);
        loadHeight(resultComponent, element);

        loadDatasource(resultComponent, element);

        loadImageResource(resultComponent, element);
    }

    protected void loadImageResource(Image resultComponent, Element element) {
        if (loadFileImageResource(resultComponent, element)) return;

        if (loadThemeImageResource(resultComponent, element)) return;

        if (loadClasspathImageResource(resultComponent, element)) return;

        loadUrlImageResource(resultComponent, element);
    }

    protected void loadUrlImageResource(Image resultComponent, Element element) {
        Element urlResource = element.element("url");
        if (urlResource == null)
            return;

        String url = urlResource.attributeValue("url");
        if (StringUtils.isEmpty(url)) {
            throw new GuiDevelopmentException("No url provided for the UrlImageResource", context.getFullFrameId());
        }

        Image.UrlImageResource resource = resultComponent.createResource(Image.UrlImageResource.class);
        try {
            resource.setUrl(new URL(url));
            resultComponent.setSource(resource);
        } catch (MalformedURLException e) {
            String msg = String.format("An error occurred while creating UrlImageResource with the given url: %s", url);
            throw new RuntimeException(msg, e);
        }
    }

    protected boolean loadClasspathImageResource(Image resultComponent, Element element) {
        Element classpathResource = element.element("classpath");
        if (classpathResource == null)
            return false;

        String classpathPath = classpathResource.attributeValue("path");
        if (StringUtils.isEmpty(classpathPath)) {
            throw new GuiDevelopmentException("No path provided for the ClasspathImageResource", context.getFullFrameId());
        }

        Image.ClasspathImageResource resource = resultComponent.createResource(Image.ClasspathImageResource.class);
        resource.setPath(classpathPath);
        resultComponent.setSource(resource);

        return true;
    }

    protected boolean loadThemeImageResource(Image resultComponent, Element element) {
        Element themeResource = element.element("theme");
        if (themeResource == null)
            return false;

        String themePath = themeResource.attributeValue("path");
        if (StringUtils.isEmpty(themePath)) {
            throw new GuiDevelopmentException("No path provided for the ThemeImageResource", context.getFullFrameId());
        }

        Image.ThemeImageResource resource = resultComponent.createResource(Image.ThemeImageResource.class);
        resource.setPath(themePath);
        resultComponent.setSource(resource);

        return true;
    }

    protected boolean loadFileImageResource(Image resultComponent, Element element) {
        Element fileResource = element.element("file");
        if (fileResource == null)
            return false;

        String filePath = fileResource.attributeValue("path");
        if (StringUtils.isEmpty(filePath)) {
            throw new GuiDevelopmentException("No path provided for the FileImageResource", context.getFullFrameId());
        }

        File file = new File(filePath);
        if (!file.exists()) {
            String msg = String.format("Can't load FileImageResource. File with given path does not exists: %s", filePath);
            throw new RuntimeException(msg);
        }

        Image.FileImageResource resource = resultComponent.createResource(Image.FileImageResource.class);
        resource.setFile(file);
        resultComponent.setSource(resource);

        return true;
    }

    protected void loadDatasource(Image component, Element element) {
        final String datasource = element.attributeValue("datasource");
        if (!StringUtils.isEmpty(datasource)) {
            Datasource ds = context.getDsContext().get(datasource);
            if (ds == null) {
                throw new GuiDevelopmentException(String.format("Datasource '%s' is not defined", datasource),
                        getContext().getFullFrameId(), "Component ID", component.getId());
            }
            String property = element.attributeValue("property");
            if (StringUtils.isEmpty(property)) {
                throw new GuiDevelopmentException(
                        String.format("Can't set datasource '%s' for component '%s' because 'property' " +
                                "attribute is not defined", datasource, component.getId()),
                        context.getFullFrameId());
            }

            component.setDatasource(ds, property);
        }
    }
}