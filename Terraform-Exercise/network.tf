resource "aws_vpc" "corral-env" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  tags = {
    Name = "mediawiki-vpc"
  }
}

resource "aws_subnet" "public" {
  cidr_block = "10.0.0.0/24"
  vpc_id = aws_vpc.corral-env.id
  map_public_ip_on_launch = "true"
  availability_zone = "us-west-2a"
  tags = {
    Name = "Public"
  }
}

resource "aws_subnet" "rds1" {
  cidr_block = "10.0.16.0/24"
  vpc_id = aws_vpc.corral-env.id
  availability_zone = "us-west-2a"
  tags = {
    Name = "RDS1"
  }
}

resource "aws_subnet" "rds2" {
  cidr_block = "10.0.17.0/24"
  vpc_id = aws_vpc.corral-env.id
  availability_zone = "us-west-2b"
  tags = {
    Name = "RDS2"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.corral-env.id
  tags = {
    Name = "mediawiki-gw"
  }
}

resource "aws_route_table" "r" {
  vpc_id = aws_vpc.corral-env.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "mediawiki public route"
  }
}

resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.r.id
}
