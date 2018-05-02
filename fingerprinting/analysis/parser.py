# -*- coding: utf-8 -*-


class MissingField(Exception):

    TEMPLATE = "[!] WARNING: mandatory field %s missing from capture"

    def __init__(self, value):
        super().__init__(self.TEMPLATE % value)


class XmlWrapper(object):

    def __init__(self, layer):
        self.layer = layer

    @property
    def type(self):
        return self.layer.attrib["name"]

    def nested(self, field):

        xml_element = self.layer.find(f'field[@name="{field}"]')

        if xml_element:
            return XmlWrapper(xml_element)
        else:
            raise MissingField(field)

    def proto(self, field):

        xml_element = self.layer.find(f'proto[@name="{field}"]')

        if xml_element is None:
            raise MissingField(field)
        else:
            return XmlWrapper(xml_element)

    def exists(self, field):

        return self.layer.find(f'field[@name="{field}"]') is not None

    def children(self, field):

        return enumerate(self.layer.findall(f'field[@name="{field}"]'))

    def integer(self, field):

        xml_element = self.layer.find(f'field[@name="{field}"]')

        if xml_element is None:
            raise MissingField(field)
        else:
            return int(xml_element.attrib["show"])

    def boolean(self, field):

        xml_element = self.layer.find(f'field[@name="{field}"]')

        if xml_element is None:
            raise MissingField(field)
        else:
            return xml_element.attrib["show"] == "1"

    def real(self, field):

        xml_element = self.layer.find(f'field[@name="{field}"]')

        if xml_element is None:
            raise MissingField(field)
        else:
            return float(xml_element.attrib["show"])

    def string(self, field):

        xml_element = self.layer.find(f'field[@name="{field}"]')

        if xml_element is None:
            raise MissingField(field)
        else:
            return str(xml_element.attrib["show"])
